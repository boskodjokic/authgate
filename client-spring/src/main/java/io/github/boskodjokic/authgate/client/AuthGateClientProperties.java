package io.github.boskodjokic.authgate.client;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Where AuthGate is, and who this service is to it.
 *
 * @param issuer AuthGate's public base URL. Its discovery document and JWKS are read from here, so
 *     this is the only address a consumer needs to know.
 * @param audience the {@code aud} this service accepts. Required: a token issued for another
 *     service must not be usable here, and there is no safe default for "any".
 */
@ConfigurationProperties(prefix = "authgate.client")
public record AuthGateClientProperties(String issuer, String audience) {

    public AuthGateClientProperties {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("authgate.client.issuer must be set");
        }
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException(
                    "authgate.client.audience must be set — without it this service would accept "
                            + "any token the issuer ever minted, including tokens meant for others");
        }
        issuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    }
}
