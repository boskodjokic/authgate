package io.github.boskodjokic.authgate.server.account;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/** A named bundle of permissions, belonging to one tenant. */
@Entity
@Table(name = "role")
public class Role {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private String name;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "permission", joinColumns = @JoinColumn(name = "role_id"))
    private Set<PermissionEntry> permissions = new LinkedHashSet<>();

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Role() {
        // for JPA
    }

    public Role(Tenant tenant, String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("role name must not be blank");
        }
        this.id = UUID.randomUUID();
        this.tenant = tenant;
        this.name = name.strip();
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public String getName() {
        return name;
    }

    public Set<PermissionEntry> getPermissions() {
        return Set.copyOf(permissions);
    }

    /** Replaces the whole grant set. Roles are edited as a unit, never patched entry by entry. */
    public void setPermissions(Collection<PermissionEntry> entries) {
        permissions.clear();
        permissions.addAll(entries);
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
