package io.github.boskodjokic.authgate.server.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * An access token withdrawn before its own expiry, named by its {@code jti}.
 *
 * <p>Access tokens are self-contained by design, which is what lets a resource server verify one
 * without calling here. The price is that withdrawing one early requires somewhere to say so.
 */
@Entity
@Table(name = "revoked_token")
public class RevokedToken {

    @Id
    private String jti;

    /** When the token would have expired anyway, after which this row can be swept. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at", nullable = false)
    private Instant revokedAt;

    protected RevokedToken() {
        // for JPA
    }

    RevokedToken(String jti, Instant expiresAt) {
        this.jti = jti;
        this.expiresAt = expiresAt;
        this.revokedAt = Instant.now();
    }

    public String getJti() {
        return jti;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}
