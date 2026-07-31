package io.github.boskodjokic.authgate.server.token;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Duration;
import java.time.Instant;

/**
 * An issued session, shaped like an OAuth 2 token response.
 *
 * <p>Shared by every route that hands out a token — magic link, federated exchange and refresh —
 * so a client parses one shape regardless of how it signed in.
 *
 * @param accessToken the signed JWT
 * @param refreshToken the single-use token that buys the next access token
 * @param tokenType always {@code Bearer}
 * @param expiresIn seconds until the access token expires
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record TokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn) {

    public static TokenResponse of(Session session) {
        long seconds =
                Duration.between(Instant.now(), session.access().expiresAt()).toSeconds();
        return new TokenResponse(session.access().value(), session.refresh(), "Bearer", Math.max(seconds, 0));
    }
}
