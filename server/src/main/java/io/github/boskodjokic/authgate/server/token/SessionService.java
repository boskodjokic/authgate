package io.github.boskodjokic.authgate.server.token;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Starts, renews and ends sessions.
 *
 * <p>A session is an access token plus a refresh token. The access token is short-lived and
 * self-contained; the refresh token is long-lived, single-use, and rotated on every renewal.
 */
@Service
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final RefreshTokenRepository refreshTokens;
    private final RevokedTokenRepository revokedTokens;
    private final AccessTokenIssuer issuer;
    private final AuthGateProperties properties;

    public SessionService(
            RefreshTokenRepository refreshTokens,
            RevokedTokenRepository revokedTokens,
            AccessTokenIssuer issuer,
            AuthGateProperties properties) {
        this.refreshTokens = refreshTokens;
        this.revokedTokens = revokedTokens;
        this.issuer = issuer;
        this.properties = properties;
    }

    /** Begins a session: a fresh access token and the first refresh token of a new family. */
    @Transactional
    public Session start(Account account, String audience) {
        IssuedToken access = issuer.issue(account, audience);
        String refresh = mintRefresh(account, UUID.randomUUID(), audience);
        return new Session(access, refresh);
    }

    /**
     * Exchanges a refresh token for a new pair, rotating it.
     *
     * <p><strong>Reuse detection.</strong> A refresh token is single-use, so presenting a spent one
     * means two parties hold it: whoever legitimately rotated it, and whoever copied it. There is
     * no way to tell which is which from the request, so the safe move is to assume the worst and
     * withdraw the entire family — ending the attacker's session and the victim's together. The
     * victim signs in again; the attacker cannot.
     *
     * @return the new pair, or empty if the token is unknown, expired, revoked or replayed
     */
    @Transactional
    public Optional<Session> refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return Optional.empty();
        }
        String tokenHash = hash(refreshToken);

        if (refreshTokens.consume(tokenHash, Instant.now()) == 0) {
            // Either it never existed, or it did and has already been spent. Only the second is a
            // replay, and only a stored row can tell us which.
            refreshTokens.findByTokenHash(tokenHash).ifPresent(this::onSuspectedReplay);
            return Optional.empty();
        }

        RefreshToken consumed = refreshTokens.findByTokenHash(tokenHash).orElseThrow();
        Account account = consumed.getAccount();
        if (!account.isActive()) {
            return Optional.empty();
        }

        IssuedToken access = issuer.issue(account, consumed.getAudience());
        String next = mintRefresh(account, consumed.getFamilyId(), consumed.getAudience());
        return Optional.of(new Session(access, next));
    }

    private void onSuspectedReplay(RefreshToken presented) {
        if (presented.isRevoked()) {
            // The family is already withdrawn; nothing further to do and nothing alarming about a
            // client retrying with a token it has not yet discarded.
            return;
        }
        log.warn(
                "Refresh token replay detected for account {} — revoking family {}",
                presented.getAccount().getId(),
                presented.getFamilyId());
        refreshTokens.revokeFamily(presented.getFamilyId(), Instant.now());
    }

    /**
     * Ends a session.
     *
     * <p>Withdraws the refresh family so no further access tokens can be minted, and denylists the
     * access token presented so the current one stops working here immediately.
     *
     * <p>The denylist is enforced by this service. A resource server that verifies a token purely
     * against the published JWKS — which is the whole point of the design — cannot see it, so an
     * already-issued access token stays valid there until it expires. That window is what the
     * short access TTL is for, and it is the same behaviour every JWT-issuing provider has.
     */
    @Transactional
    public void end(String refreshToken, String accessTokenJti, Instant accessTokenExpiry) {
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokens
                    .findByTokenHash(hash(refreshToken))
                    .ifPresent(token -> refreshTokens.revokeFamily(token.getFamilyId(), Instant.now()));
        }
        if (accessTokenJti != null && !accessTokenJti.isBlank() && !revokedTokens.existsByJti(accessTokenJti)) {
            revokedTokens.save(new RevokedToken(accessTokenJti, accessTokenExpiry));
        }
    }

    /** Whether an access token has been withdrawn. Consulted on every authenticated request. */
    @Transactional(readOnly = true)
    public boolean isRevoked(String jti) {
        return jti != null && revokedTokens.existsByJti(jti);
    }

    private String mintRefresh(Account account, UUID familyId, String audience) {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        refreshTokens.save(new RefreshToken(
                hash(token), account, familyId, audience, Instant.now().plus(properties.refreshTokenTtl())));
        return token;
    }

    /**
     * SHA-256, unsalted. The input is 256 bits of uniform randomness, so there is no dictionary to
     * attack and a work factor would buy nothing; what the hash prevents is a leaked table being a
     * set of directly usable sessions.
     */
    static String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable on this JVM", e);
        }
    }
}
