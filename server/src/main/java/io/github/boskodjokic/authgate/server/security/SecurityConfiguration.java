package io.github.boskodjokic.authgate.server.security;

import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.crypto.SigningKeys;
import io.github.boskodjokic.authgate.server.token.AccessTokenIssuer;
import io.github.boskodjokic.authgate.server.token.SessionService;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Protects the admin API with the service's own tokens.
 *
 * <p>AuthGate is its own first consumer here, and deliberately so: the admin API is verified by
 * Spring's standard {@code oauth2-resource-server}, reading the same {@code perms} claim any other
 * service would. If that arrangement did not work, the central claim of the project — that any
 * conforming client can consume these tokens — would be false, and this configuration is where it
 * would show.
 */
@Configuration
@EnableMethodSecurity
public class SecurityConfiguration {

    /** Authority granted to a superuser, checked alongside every specific permission. */
    public static final String SUPERUSER = "superuser";

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.csrf(csrf -> csrf.disable())
                // No cookies and no sessions: every request carries its own bearer token, which is
                // also why disabling CSRF here is safe rather than merely convenient.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(requests -> requests
                        // A client that had to authenticate before it could discover how to
                        // authenticate would not be usable by any stock OIDC library.
                        .requestMatchers(HttpMethod.GET, "/.well-known/**")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health")
                        .permitAll()
                        // Spring forwards a failed request to /error. Without this, a 400 from
                        // bean validation is re-decided by the error dispatch and reaches the
                        // caller as a 401 — a misleading answer to a request that was permitted.
                        .requestMatchers("/error")
                        .permitAll()
                        // The redemption page is reached by someone who is, by definition, not yet
                        // signed in.
                        .requestMatchers(HttpMethod.GET, "/signin/**")
                        .permitAll()
                        // Ending a session requires proving you hold it. Left public, anyone could
                        // end anyone else's by guessing at refresh tokens.
                        .requestMatchers(HttpMethod.POST, "/auth/logout")
                        .authenticated()
                        // The remaining sign-in routes are how a caller obtains a token in the
                        // first place, and /auth/refresh is reached when the access token has
                        // usually already expired. They defend themselves: see MagicLinkService,
                        // FederationService and SessionService.
                        .requestMatchers(HttpMethod.POST, "/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // This origin serves both the identity service and a page, so script injection
                // here would be a compromise of identity rather than a defacement. The policy
                // allows no inline script and no inline style, which is why the sign-in page keeps
                // its JavaScript and CSS in separate files.
                .headers(headers -> headers.contentSecurityPolicy(
                                csp -> csp.policyDirectives("default-src 'none'; script-src 'self'; style-src 'self'; "
                                        + "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                                        + "form-action 'none'; frame-ancestors 'none'"))
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(referrer -> referrer.policy(
                                org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter
                                        .ReferrerPolicy.NO_REFERRER)))
                .build();
    }

    /**
     * Verifies our own tokens from the in-memory key rather than by fetching our own JWKS over
     * HTTP. Same validation, no round trip to ourselves, and no dependency on being able to reach
     * our own public URL from inside the container.
     */
    @Bean
    JwtDecoder jwtDecoder(SigningKeys keys, AuthGateProperties properties, SessionService sessions) {
        // One key, so the public key is handed over directly. When rotation lands and there are
        // several, this becomes a JWK source keyed by kid — the header already carries one.
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        // Issuer is checked as well as signature and expiry: a correctly signed token is not
        // automatically one we minted for this deployment. The denylist is checked alongside, so a
        // token withdrawn by logout stops working here at once rather than at expiry.
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()), new NotRevoked(sessions)));
        return decoder;
    }

    /**
     * Rejects an access token that has been withdrawn.
     *
     * <p>Only this service consults the denylist. A resource server verifying against the published
     * JWKS — which is the entire point of the design — cannot see it, so a token already in the
     * wild stays valid there until it expires. That window is what the short access TTL bounds, and
     * it is how every JWT-issuing provider behaves; revocation is authoritative at the refresh
     * boundary, where no new token can be obtained.
     */
    private record NotRevoked(SessionService sessions) implements OAuth2TokenValidator<Jwt> {

        private static final OAuth2Error REVOKED = new OAuth2Error("invalid_token", "The token has been revoked", null);

        @Override
        public OAuth2TokenValidatorResult validate(Jwt token) {
            return sessions.isRevoked(token.getId())
                    ? OAuth2TokenValidatorResult.failure(REVOKED)
                    : OAuth2TokenValidatorResult.success();
        }
    }

    /**
     * Turns the {@code perms} claim into authorities of the form {@code resource:action}, plus
     * {@code superuser} where the claim says so.
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();
            Map<String, Object> perms = jwt.getClaimAsMap("perms");
            if (perms != null) {
                AccessTokenIssuer.authorities(perms).stream()
                        .map(SimpleGrantedAuthority::new)
                        .forEach(authorities::add);
            }
            if (Boolean.TRUE.equals(jwt.getClaim("superuser"))) {
                authorities.add(new SimpleGrantedAuthority(SUPERUSER));
            }
            return authorities;
        });
        return converter;
    }
}
