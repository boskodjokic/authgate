package io.github.boskodjokic.authgate.server.token;

import java.time.Instant;

/**
 * A freshly minted access token.
 *
 * @param value the compact-serialised JWS
 * @param expiresAt when it stops being valid
 */
public record IssuedToken(String value, Instant expiresAt) {}
