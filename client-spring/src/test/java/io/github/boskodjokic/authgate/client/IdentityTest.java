package io.github.boskodjokic.authgate.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/** Reading a caller out of a verified token. */
class IdentityTest {

    private static Jwt jwt(Map<String, Object> claims) {
        Map<String, Object> all = new java.util.LinkedHashMap<>(claims);
        all.putIfAbsent("sub", "account-1");
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claims(existing -> existing.putAll(all))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(900))
                .build();
    }

    @Test
    void readsTheClaimsAServiceActuallyNeeds() {
        Identity identity = Identity.of(jwt(Map.of(
                "tenant", "tenant-1",
                "email", "bosko@example.test",
                "perms", Map.of("material", List.of("read", "update")))));

        assertThat(identity.accountId()).isEqualTo("account-1");
        assertThat(identity.tenantId()).isEqualTo("tenant-1");
        assertThat(identity.email()).isEqualTo("bosko@example.test");
        assertThat(identity.permissions()).containsOnlyKeys("material");
    }

    @Test
    void aTokenWithNoPermissionsGrantsNothing() {
        Identity identity = Identity.of(jwt(Map.of("tenant", "tenant-1", "email", "nobody@example.test")));

        // An absent perms claim must read as "no permissions", never as a wildcard.
        assertThat(identity.permissions()).isEmpty();
        assertThat(identity.may("material", "read")).isFalse();
        assertThat(identity.authorities()).isEmpty();
    }

    @Test
    void grantsAreCheckedByResourceAndAction() {
        Identity identity = Identity.of(jwt(Map.of("perms", Map.of("material", List.of("read")))));

        assertThat(identity.may("material", "read")).isTrue();
        assertThat(identity.may("material", "update")).isFalse();
        assertThat(identity.may("colourway", "read")).isFalse();
    }

    @Test
    void aSuperuserPassesEverything() {
        Identity identity = Identity.of(jwt(Map.of("superuser", true)));

        assertThat(identity.may("anything", "at-all")).isTrue();
        assertThat(identity.authorities()).containsExactly("superuser");
    }

    @Test
    void authoritiesAreTheStringsSpringSecurityMatchesOn() {
        Identity identity = Identity.of(jwt(Map.of("perms", Map.of("material", List.of("read", "update")))));

        // These are what @PreAuthorize("hasAuthority('material:update')") compares against.
        assertThat(identity.authorities()).containsExactlyInAnyOrder("material:read", "material:update");
    }

    @Test
    void permissionsCannotBeMutatedThroughTheRecord() {
        Identity identity = Identity.of(jwt(Map.of("perms", Map.of("material", List.of("read")))));

        // A caller's granted set is not somewhere a handler gets to write.
        assertThat(identity.permissions()).isUnmodifiable();
    }
}
