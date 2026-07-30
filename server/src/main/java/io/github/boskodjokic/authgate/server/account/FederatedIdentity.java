package io.github.boskodjokic.authgate.server.account;

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
 * A link from one external identity provider's view of a person to a local {@link Account}.
 *
 * <p>The pair (issuer, subject) is unique across the whole table and is the only supported way to
 * reach an account from a federated token. Matching on email instead would mean that any provider
 * able to assert an address could reach an account created through a different one.
 */
@Entity
@Table(name = "federated_identity")
public class FederatedIdentity {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "account_id", nullable = false)
    private Account account;

    /** The {@code iss} claim exactly as the provider asserts it. */
    @Column(nullable = false)
    private String issuer;

    /** The {@code sub} claim — opaque, provider-scoped, and stable across email changes. */
    @Column(nullable = false)
    private String subject;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected FederatedIdentity() {
        // for JPA
    }

    public FederatedIdentity(Account account, String issuer, String subject) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        this.id = UUID.randomUUID();
        this.account = account;
        this.issuer = issuer;
        this.subject = subject;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public Account getAccount() {
        return account;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getSubject() {
        return subject;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
