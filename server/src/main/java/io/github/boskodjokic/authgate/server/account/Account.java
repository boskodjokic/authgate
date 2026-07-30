package io.github.boskodjokic.authgate.server.account;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/**
 * A person or service known to one tenant.
 *
 * <p>Note the absence of any credential field. Sign-in happens by federation or by emailed link,
 * so there is nothing here for a database leak to turn into an account takeover.
 */
@Entity
@Table(name = "account")
public class Account {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    /**
     * Contact address, and the target of a magic link. Deliberately <em>not</em> an identity key:
     * federated lookups go through {@link FederatedIdentity} on (issuer, subject).
     */
    @Column(nullable = false)
    private String email;

    @Column(name = "display_name")
    private String displayName;

    @Column(nullable = false)
    private boolean active;

    @Column(nullable = false)
    private boolean superuser;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Account() {
        // for JPA
    }

    public Account(Tenant tenant, String email, String displayName) {
        this.id = UUID.randomUUID();
        this.tenant = tenant;
        this.email = normalizeEmail(email);
        this.displayName = displayName;
        this.active = true;
        this.superuser = false;
        this.createdAt = Instant.now();
    }

    /**
     * Addresses are stored lowercased and trimmed. The uniqueness constraint is a plain unique
     * index, so without normalising on the way in, {@code Bosko@example.com} and
     * {@code bosko@example.com} would become two accounts and a magic link would be ambiguous.
     */
    public static String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        return email.strip().toLowerCase(Locale.ROOT);
    }

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public String getEmail() {
        return email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isActive() {
        return active;
    }

    public void deactivate() {
        this.active = false;
    }

    public boolean isSuperuser() {
        return superuser;
    }

    public void grantSuperuser() {
        this.superuser = true;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
