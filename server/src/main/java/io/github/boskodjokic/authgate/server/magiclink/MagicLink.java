package io.github.boskodjokic.authgate.server.magiclink;

import io.github.boskodjokic.authgate.server.account.Account;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A one-time sign-in token, stored only as a hash.
 *
 * <p>The plaintext token exists in exactly two places: the email that was sent, and the request
 * that redeems it. It is never persisted, so reading this table gives an attacker nothing to
 * present.
 */
@Entity
@Table(name = "magic_link")
public class MagicLink {

    @Id
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    @Column(nullable = false)
    private String audience;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected MagicLink() {
        // for JPA
    }

    MagicLink(String tokenHash, Account account, String audience, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.account = account;
        this.audience = audience;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
    }

    /** The stored SHA-256 of the token. The token itself is never persisted. */
    public String getTokenHash() {
        return tokenHash;
    }

    public Account getAccount() {
        return account;
    }

    public String getAudience() {
        return audience;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean hasExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /** Marks the link used. Only the redemption path calls this, inside the same transaction. */
    void consume(Instant when) {
        this.consumedAt = when;
    }
}
