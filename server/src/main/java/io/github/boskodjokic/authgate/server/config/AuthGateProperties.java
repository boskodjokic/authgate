package io.github.boskodjokic.authgate.server.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Root configuration for the service.
 *
 * @param issuer the public base URL clients will see in the {@code iss} claim and in the discovery
 *     document. Must match how callers actually reach the service, because verifiers compare it
 *     against the token's issuer exactly.
 * @param accessTokenTtl how long an access token stays valid. Kept short by default: permissions
 *     travel inside the token, so a revoked role is only truly gone once the token expires.
 * @param signing signing key material.
 * @param magicLink passwordless email sign-in.
 */
@ConfigurationProperties(prefix = "authgate")
public record AuthGateProperties(String issuer, Duration accessTokenTtl, Signing signing, MagicLink magicLink) {

    public AuthGateProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("authgate.issuer must be set");
        }
        if (issuer.endsWith("/")) {
            // A trailing slash silently produces "https://host//.well-known/..." and an `iss`
            // claim that fails exact-match comparison at every verifier.
            throw new IllegalArgumentException("authgate.issuer must not end with '/': " + issuer);
        }
        if (accessTokenTtl == null || accessTokenTtl.isNegative() || accessTokenTtl.isZero()) {
            throw new IllegalArgumentException("authgate.access-token-ttl must be positive");
        }
        if (signing == null) {
            signing = new Signing(null);
        }
        if (magicLink == null) {
            magicLink = new MagicLink(null, null, null, null);
        }
    }

    /**
     * Key material this service signs tokens with.
     *
     * @param privateKey a PKCS#8 PEM-encoded RSA private key. When blank, an ephemeral key is
     *     generated at startup — usable for development, useless across a restart, and unfit for
     *     any deployment where another instance or another lifetime has to verify the result.
     */
    public record Signing(String privateKey) {}

    /**
     * Passwordless email sign-in.
     *
     * @param ttl how long a link stays redeemable. Short by design: it is a bearer credential
     *     sitting in an inbox.
     * @param audience the {@code aud} of the access token a redeemed link produces. Fixed by
     *     configuration rather than taken from the request, or any caller could mint a token for
     *     a service it was never entitled to reach.
     * @param redirectBase the page the emailed link points at. It receives the token in the URL
     *     fragment and posts it back to the redeem endpoint.
     * @param from the envelope sender for the email.
     */
    public record MagicLink(Duration ttl, String audience, String redirectBase, String from) {

        public MagicLink {
            ttl = ttl == null ? Duration.ofMinutes(10) : ttl;
            from = from == null || from.isBlank() ? "no-reply@localhost" : from;
            if (ttl.isNegative() || ttl.isZero()) {
                throw new IllegalArgumentException("authgate.magic-link.ttl must be positive");
            }
        }
    }
}
