package io.github.boskodjokic.authgate.server.federation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies tokens from one OpenID Connect provider.
 *
 * <p>The security-relevant choices, stated because these are the ones usually got wrong:
 *
 * <ul>
 *   <li>Accepted algorithms are fixed in code, never read from the token header. Taking the
 *       algorithm from the token is what makes {@code alg: none} and RSA/HMAC confusion possible.
 *   <li>Both {@code iss} and {@code aud} are verified, and {@code exp} is required.
 *   <li>Key fetching, caching, rate limiting and refetch-on-unknown-{@code kid} are delegated to
 *       Nimbus's {@code JWKSourceBuilder}. Hand-rolling that is how an unknown {@code kid} turns
 *       into an unbounded stream of requests at the provider.
 *   <li>Discovery is lazy. Resolving every provider at startup would make this service refuse to
 *       boot because someone else's IdP is having an outage.
 * </ul>
 */
class OidcProvider {

    private static final Logger log = LoggerFactory.getLogger(OidcProvider.class);

    /** Providers that matter all sign with RS256; anything else is rejected outright. */
    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS =
            Set.of(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512);

    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);

    private final FederatedProviderProperties config;
    private final HttpClient http;
    private volatile DefaultJWTProcessor<SecurityContext> processor;

    OidcProvider(FederatedProviderProperties config) {
        this.config = config;
        this.http = HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build();
    }

    FederatedProviderProperties config() {
        return config;
    }

    /**
     * Verifies a token and extracts the caller.
     *
     * @throws FederationException if the token is not valid for this provider
     */
    Principal verify(String token) {
        JWTClaimsSet claims;
        try {
            claims = processor().process(token, null);
        } catch (Exception e) {
            // The provider name is safe to surface; the parse detail is not, so it is logged
            // rather than returned.
            log.debug("{}: token rejected", config.name(), e);
            throw new FederationException(config.name() + ": token verification failed");
        }

        Object subject = claims.getClaim(config.subjectClaim());
        if (subject == null || subject.toString().isBlank()) {
            throw new FederationException(config.name() + ": token has no " + config.subjectClaim() + " claim");
        }

        Object email = claims.getClaim(config.emailClaim());
        Object verified = claims.getClaim(config.emailVerifiedClaim());

        return new Principal(
                config.name(),
                config.issuer(),
                subject.toString(),
                email == null ? null : email.toString().strip().toLowerCase(Locale.ROOT),
                Boolean.TRUE.equals(verified) || "true".equals(String.valueOf(verified)));
    }

    private DefaultJWTProcessor<SecurityContext> processor() {
        DefaultJWTProcessor<SecurityContext> existing = processor;
        if (existing != null) {
            return existing;
        }
        synchronized (this) {
            if (processor == null) {
                processor = buildProcessor(discoverJwksUri());
            }
            return processor;
        }
    }

    private DefaultJWTProcessor<SecurityContext> buildProcessor(URL jwksUri) {
        JWKSource<SecurityContext> keys =
                JWKSourceBuilder.create(jwksUri).retrying(true).build();

        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS, keys));
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                config.audience(),
                new JWTClaimsSet.Builder().issuer(config.issuer()).build(),
                Set.of("sub", "iat", "exp")));
        return jwtProcessor;
    }

    private URL discoverJwksUri() {
        String url = config.issuer() + "/.well-known/openid-configuration";
        try {
            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(URI.create(url))
                            .timeout(HTTP_TIMEOUT)
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new FederationException(config.name() + ": discovery returned HTTP " + response.statusCode());
            }

            Map<?, ?> document =
                    new com.fasterxml.jackson.databind.ObjectMapper().readValue(response.body(), Map.class);

            // The document arrives over TLS from the issuer, but its own `issuer` field must still
            // match what we configured. Without this check a redirect could quietly point us at a
            // different provider's keys, and every token it signs would then verify.
            Object declared = document.get("issuer");
            String normalised = declared == null ? null : declared.toString().replaceAll("/$", "");
            if (!config.issuer().equals(normalised)) {
                throw new FederationException(config.name() + ": discovery issuer '" + declared
                        + "' does not match configured '" + config.issuer() + "'");
            }

            Object jwksUri = document.get("jwks_uri");
            if (jwksUri == null) {
                throw new FederationException(config.name() + ": discovery document has no jwks_uri");
            }
            return URI.create(jwksUri.toString()).toURL();
        } catch (FederationException e) {
            throw e;
        } catch (IOException | InterruptedException | RuntimeException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new FederationException(config.name() + ": could not read discovery document", e);
        }
    }
}
