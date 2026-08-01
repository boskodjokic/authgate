package io.github.boskodjokic.authgate.client;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * The caller, as an AuthGate token describes them.
 *
 * <p>A typed view over the claims, so a service is not reaching into a {@code Map} for
 * {@code "tenant"} in every handler and guessing at the shape of {@code "perms"}.
 *
 * @param accountId the {@code sub} claim — AuthGate's account id, not the external provider's
 *     subject. A service never needs to know which identity provider someone came through.
 * @param tenantId the tenant this caller belongs to
 * @param email their address, for display and audit
 * @param superuser whether every permission check passes for them
 * @param permissions granted actions, keyed by resource
 */
public record Identity(
        String accountId, String tenantId, String email, boolean superuser, Map<String, Set<String>> permissions) {

    public Identity {
        permissions = permissions == null ? Map.of() : Map.copyOf(permissions);
    }

    /** Reads an identity out of a verified token. */
    public static Identity of(Jwt jwt) {
        Map<String, Object> claims = jwt.getClaimAsMap("perms");
        Map<String, Set<String>> permissions = new java.util.LinkedHashMap<>();
        if (claims != null) {
            claims.forEach((resource, actions) -> permissions.put(resource, toSet(actions)));
        }
        return new Identity(
                jwt.getSubject(),
                jwt.getClaimAsString("tenant"),
                jwt.getClaimAsString("email"),
                Boolean.TRUE.equals(jwt.getClaim("superuser")),
                permissions);
    }

    private static Set<String> toSet(Object actions) {
        if (actions instanceof Collection<?> collection) {
            Set<String> values = new LinkedHashSet<>();
            collection.forEach(action -> values.add(String.valueOf(action)));
            return values;
        }
        return Set.of();
    }

    /**
     * Whether this caller may take an action on a resource.
     *
     * <p>Superusers pass everything, matching the service's own rule. Provided so a check reads the
     * same in code as it does in a {@code @PreAuthorize} expression.
     */
    public boolean may(String resource, String action) {
        return superuser || permissions.getOrDefault(resource, Set.of()).contains(action);
    }

    /** The authority strings Spring Security matches on, as {@code resource:action}. */
    public List<String> authorities() {
        List<String> authorities = new java.util.ArrayList<>();
        permissions.forEach((resource, actions) -> actions.forEach(action -> authorities.add(resource + ":" + action)));
        if (superuser) {
            authorities.add("superuser");
        }
        return List.copyOf(authorities);
    }
}
