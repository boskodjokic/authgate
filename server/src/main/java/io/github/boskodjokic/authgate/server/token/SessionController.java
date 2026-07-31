package io.github.boskodjokic.authgate.server.token;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Renewing and ending a session. */
@RestController
@RequestMapping("/auth")
public class SessionController {

    private final SessionService sessions;

    public SessionController(SessionService sessions) {
        this.sessions = sessions;
    }

    /**
     * Exchanges a refresh token for a new pair.
     *
     * <p>Unauthenticated on purpose: the refresh token <em>is</em> the credential, and the access
     * token it replaces has usually expired by the time a client gets here.
     *
     * <p>A 401 covers unknown, expired, revoked and replayed alike. A caller learning that its
     * token was rejected specifically for being a replay would learn that someone else is using it,
     * which is information for an attacker rather than for a client.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest body) {
        return sessions.refresh(body.refreshToken())
                .map(session -> ResponseEntity.ok(TokenResponse.of(session)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    /**
     * Ends a session.
     *
     * <p>Requires a valid access token, so that one caller cannot end another's session by
     * guessing at refresh tokens. The refresh token in the body names the family to withdraw; the
     * bearer token names itself for the denylist.
     */
    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@AuthenticationPrincipal Jwt accessToken, @RequestBody(required = false) LogoutRequest body) {
        Instant expiry = accessToken.getExpiresAt() == null ? Instant.now() : accessToken.getExpiresAt();
        sessions.end(body == null ? null : body.refreshToken(), accessToken.getId(), expiry);
    }

    /**
     * A renewal attempt.
     *
     * @param refreshToken the token issued alongside the access token being replaced
     */
    public record RefreshRequest(@JsonAlias("refresh_token") @NotBlank String refreshToken) {}

    /**
     * A logout request.
     *
     * @param refreshToken the session's refresh token, so its whole family can be withdrawn
     */
    public record LogoutRequest(@JsonAlias("refresh_token") String refreshToken) {}
}
