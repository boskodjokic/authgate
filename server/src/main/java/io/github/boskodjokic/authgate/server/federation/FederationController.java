package io.github.boskodjokic.authgate.server.federation;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.boskodjokic.authgate.server.token.IssuedToken;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exchanges a token from a configured identity provider for one of ours.
 *
 * <p><strong>Why exchange rather than an authorization-code flow.</strong> This endpoint expects
 * the client to have already signed in with the provider — through Google's or Microsoft's own
 * SDK, typically — and to present the resulting ID token. That suits a single-page or mobile app,
 * which is where these providers' own libraries already live, and it keeps this service free of
 * redirect handling, client secrets and callback state.
 *
 * <p>The cost is that it does not serve a plain server-rendered application, which needs the
 * redirect dance. That is a later addition, not a replacement: both flows end at the same
 * verification and the same account lookup.
 */
@RestController
@RequestMapping("/auth/federated")
public class FederationController {

    private static final Logger log = LoggerFactory.getLogger(FederationController.class);

    private final FederationService service;

    public FederationController(FederationService service) {
        this.service = service;
    }

    @PostMapping("/exchange")
    public TokenResponse exchange(@Valid @RequestBody ExchangeRequest body) {
        return TokenResponse.of(service.exchange(body.token()));
    }

    /**
     * Every federation failure is a 401 with no detail.
     *
     * <p>The reason is logged, not returned. "No account is linked to this Google subject" tells a
     * caller that their token verified — which is to say, it confirms the token is genuine and
     * that the only thing standing between them and a session is provisioning.
     */
    @ExceptionHandler(FederationException.class)
    ResponseEntity<Void> onFederationFailure(FederationException e) {
        log.info("Federated exchange rejected: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    /**
     * A token from an external provider.
     *
     * @param token the provider's ID token, compact-serialised
     */
    public record ExchangeRequest(@NotBlank String token) {}

    /**
     * An issued access token, shaped like an OAuth 2 token response.
     *
     * @param accessToken the signed JWT
     * @param tokenType always {@code Bearer}
     * @param expiresIn seconds until expiry
     */
    public record TokenResponse(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") long expiresIn) {

        static TokenResponse of(IssuedToken token) {
            long seconds = Duration.between(Instant.now(), token.expiresAt()).toSeconds();
            return new TokenResponse(token.value(), "Bearer", Math.max(seconds, 0));
        }
    }
}
