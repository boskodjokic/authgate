package io.github.boskodjokic.authgate.server.magiclink;

import io.github.boskodjokic.authgate.server.token.Session;
import io.github.boskodjokic.authgate.server.token.TokenResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Passwordless sign-in by emailed link.
 *
 * <p><strong>Why redemption is a POST.</strong> The obvious design puts the token in the emailed
 * URL and redeems on GET. It does not survive contact with real mail: link scanners and inbox
 * prefetchers — Outlook Safe Links and similar — fetch every URL in a message before the recipient
 * sees it, and a single-use token is spent by the time it is clicked. So the emailed link points
 * at a page, carries the token in the fragment, and that page posts it back here. Fragments are
 * never sent to a server, which keeps the token out of access logs and {@code Referer} headers as
 * well.
 */
@RestController
@RequestMapping("/auth/magic-link")
public class MagicLinkController {

    private final MagicLinkService service;

    public MagicLinkController(MagicLinkService service) {
        this.service = service;
    }

    /** Request a link. Always 202, whether or not the address matches an account. */
    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void request(@Valid @RequestBody LinkRequest body) {
        service.request(body.tenant(), body.email());
    }

    /** Redeem a link. */
    @PostMapping("/redeem")
    public ResponseEntity<TokenResponse> redeem(@Valid @RequestBody RedeemRequest body) {
        Optional<Session> session = service.redeem(body.token());

        // One response for unknown, spent and expired alike. Telling them apart would let a
        // holder of a stolen link learn whether it had already been used, and by extension
        // whether the victim has signed in yet.
        return session.map(started -> ResponseEntity.ok(TokenResponse.of(started)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    /**
     * A request for a sign-in link.
     *
     * @param tenant slug of the tenant the account belongs to
     * @param email the address to send to
     */
    public record LinkRequest(@NotBlank String tenant, @NotBlank @Email String email) {}

    /**
     * A redemption attempt.
     *
     * @param token the value taken from the emailed link's fragment
     */
    public record RedeemRequest(@NotBlank String token) {}
}
