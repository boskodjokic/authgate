package io.github.boskodjokic.authgate.server.token;

/**
 * A newly started or renewed session.
 *
 * @param access the short-lived access token
 * @param refresh the single-use refresh token that will buy the next one
 */
public record Session(IssuedToken access, String refresh) {}
