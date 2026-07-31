package io.github.boskodjokic.authgate.server.token;

import io.github.boskodjokic.authgate.server.account.Account;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A long-lived, single-use token that buys a new access token.
 *
 * <p>Stored only as a hash. Members of one sign-in share a {@code familyId}, which is what makes
 * reuse detection possible: presenting a token that has already been spent means two parties hold
 * it, and since there is no way to tell the thief from the victim, the entire family is withdrawn.
 */
@Entity
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(nullable = false)
    private String audience;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected RefreshToken() {
        // for JPA
    }

    RefreshToken(String tokenHash, Account account, UUID familyId, String audience, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.account = account;
        this.familyId = familyId;
        this.audience = audience;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Account getAccount() {
        return account;
    }

    public UUID getFamilyId() {
        return familyId;
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

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
