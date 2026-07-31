package io.github.boskodjokic.authgate.server.account;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import java.util.Locale;
import java.util.Objects;

/**
 * A single grant: one action on one resource.
 *
 * <p>Both halves are normalised to lower case. The table's primary key is a plain composite, so
 * without normalising, {@code Material/UPDATE} and {@code material/update} would be two rows and
 * the effective policy would depend on how someone typed it.
 */
@Embeddable
public class PermissionEntry {

    @Column(nullable = false)
    private String resource;

    @Column(nullable = false)
    private String action;

    protected PermissionEntry() {
        // for JPA
    }

    public PermissionEntry(String resource, String action) {
        this.resource = normalize(resource, "resource");
        this.action = normalize(action, "action");
    }

    private static String normalize(String value, String what) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(what + " must not be blank");
        }
        return value.strip().toLowerCase(Locale.ROOT);
    }

    public String getResource() {
        return resource;
    }

    public String getAction() {
        return action;
    }

    /** The form carried in a token and matched by an authority check. */
    public String asAuthority() {
        return resource + ":" + action;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof PermissionEntry entry)) {
            return false;
        }
        return resource.equals(entry.resource) && action.equals(entry.action);
    }

    @Override
    public int hashCode() {
        return Objects.hash(resource, action);
    }

    @Override
    public String toString() {
        return asAuthority();
    }
}
