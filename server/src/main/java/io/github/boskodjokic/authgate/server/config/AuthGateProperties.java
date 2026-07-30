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
 */
@ConfigurationProperties(prefix = "authgate")
public record AuthGateProperties(String issuer, Duration accessTokenTtl, Signing signing) {

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
    }

    /**
     * Key material this service signs tokens with.
     *
     * @param privateKey a PKCS#8 PEM-encoded RSA private key. When blank, an ephemeral key is
     *     generated at startup — usable for development, useless across a restart, and unfit for
     *     any deployment where another instance or another lifetime has to verify the result.
     */
    public record Signing(String privateKey) {}
}
