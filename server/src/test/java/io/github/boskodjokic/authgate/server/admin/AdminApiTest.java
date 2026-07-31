package io.github.boskodjokic.authgate.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.FederatedIdentityRepository;
import io.github.boskodjokic.authgate.server.account.PermissionEntry;
import io.github.boskodjokic.authgate.server.account.Role;
import io.github.boskodjokic.authgate.server.account.RoleRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import io.github.boskodjokic.authgate.server.token.AccessTokenIssuer;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * The admin API, and the permission model that guards it.
 *
 * <p>Tokens here are minted by the service's own issuer and presented over HTTP, so these tests
 * exercise the full path a real caller takes: claim to authority conversion, method security, and
 * the resource/action model end to end.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class AdminApiTest {

    private static final String AUDIENCE = "http://localhost:8080";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void noBootstrap(DynamicPropertyRegistry registry) {
        // These tests create their own accounts; the bootstrap path has its own test.
        registry.add("authgate.bootstrap.email", () -> "");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private TenantRepository tenants;

    @Autowired
    private AccountRepository accounts;

    @Autowired
    private RoleRepository roles;

    @Autowired
    private FederatedIdentityRepository identities;

    @Autowired
    private AccessTokenIssuer issuer;

    private Tenant acme;

    @BeforeEach
    void setUp() {
        identities.deleteAll();
        accounts.deleteAll();
        roles.deleteAll();
        tenants.deleteAll();
        acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
    }

    private String tokenFor(Account account) {
        return issuer.issue(account, AUDIENCE).value();
    }

    /** An account holding exactly the named grants, and nothing else. */
    private Account accountWith(String email, String... grants) {
        Account account = accounts.saveAndFlush(new Account(acme, email, email));
        if (grants.length > 0) {
            Role role = new Role(acme, "role-for-" + email);
            role.setPermissions(List.of(grants).stream()
                    .map(grant -> {
                        String[] parts = grant.split(":", -1);
                        return new PermissionEntry(parts[0], parts[1]);
                    })
                    .toList());
            roles.saveAndFlush(role);
            account.setRoles(List.of(role));
            accounts.saveAndFlush(account);
        }
        return accounts.findById(account.getId()).orElseThrow();
    }

    private Account superuser() {
        Account account = accounts.saveAndFlush(new Account(acme, "root@example.test", "Root"));
        account.grantSuperuser();
        return accounts.saveAndFlush(account);
    }

    private <T> ResponseEntity<T> call(HttpMethod method, String path, String token, Object body, Class<T> type) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return restTemplate.exchange("http://localhost:" + port + path, method, new HttpEntity<>(body, headers), type);
    }

    // -- authentication and authorisation ----------------------------------

    @Test
    void anAnonymousCallerIsRefused() {
        assertThat(call(HttpMethod.GET, "/admin/tenants", null, null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aGarbageTokenIsRefused() {
        assertThat(call(HttpMethod.GET, "/admin/tenants", "not-a-token", null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void anAuthenticatedCallerWithoutThePermissionIsForbidden() {
        // Authenticated, so not a 401 — but holding no grant that covers this route. The
        // distinction matters: 401 means "say who you are", 403 means "you did, and it is not
        // enough".
        String token = tokenFor(accountWith("nobody@example.test"));

        assertThat(call(HttpMethod.GET, "/admin/tenants", token, null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void aGrantOnAnotherResourceDoesNotOpenThisOne() {
        // account:read is a real grant, just not this one. A model where any permission implies
        // any other is not a model.
        String token = tokenFor(accountWith("reader@example.test", "account:read"));

        assertThat(call(HttpMethod.GET, "/admin/tenants", token, null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void aGrantOnTheRightResourceButTheWrongActionDoesNotOpenIt() {
        String token = tokenFor(accountWith("reader@example.test", "tenant:read"));

        assertThat(call(HttpMethod.POST, "/admin/tenants", token, Map.of("slug", "x", "name", "X"), String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void theMatchingGrantOpensTheRoute() {
        String token = tokenFor(accountWith("reader@example.test", "tenant:read"));

        assertThat(call(HttpMethod.GET, "/admin/tenants", token, null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void aSuperuserNeedsNoSpecificGrant() {
        String token = tokenFor(superuser());

        assertThat(call(HttpMethod.GET, "/admin/tenants", token, null, String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);
    }

    // -- the token carries the policy ---------------------------------------

    @Test
    void anIssuedTokenCarriesTheAccountsPermissions() throws Exception {
        Account account = accountWith("editor@example.test", "material:read", "material:update");

        SignedJWT jwt = SignedJWT.parse(tokenFor(account));
        Map<String, Object> perms = jwt.getJWTClaimsSet().getJSONObjectClaim("perms");

        // Verifiers read this claim instead of calling back here, which is what lets a resource
        // server check a permission with no network hop.
        assertThat(perms).containsOnlyKeys("material");
        List<String> actions =
                ((List<?>) perms.get("material")).stream().map(String::valueOf).toList();
        // Sorted, so the claim is byte-identical for two accounts with the same policy.
        assertThat(actions).containsExactly("read", "update");
        assertThat(jwt.getJWTClaimsSet().getClaim("superuser")).isEqualTo(false);
    }

    @Test
    void aTokenIssuedBeforeARoleChangeStillCarriesTheOldPolicy() throws Exception {
        Account account = accountWith("editor@example.test", "material:read");
        String stale = tokenFor(account);

        account.setRoles(List.of());
        accounts.saveAndFlush(account);

        // Documented consequence of putting permissions in the token, not a defect: the grant
        // survives until expiry. It is the reason the default TTL is minutes, and the reason
        // phase 5 adds revocation.
        SignedJWT jwt = SignedJWT.parse(stale);
        assertThat(jwt.getJWTClaimsSet().getJSONObjectClaim("perms")).containsKey("material");
    }

    // -- administration ------------------------------------------------------

    @Test
    void aSuperuserCanCreateATenantAnAccountARoleAndALink() {
        String token = tokenFor(superuser());

        assertThat(call(
                                HttpMethod.POST,
                                "/admin/tenants",
                                token,
                                Map.of("slug", "globex", "name", "Globex"),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.CREATED);

        @SuppressWarnings("unchecked")
        Class<Map<String, Object>> mapType = (Class<Map<String, Object>>) (Class<?>) Map.class;
        ResponseEntity<Map<String, Object>> created = call(
                HttpMethod.POST,
                "/admin/tenants/globex/accounts",
                token,
                Map.of("email", "new@example.test", "displayName", "New"),
                mapType);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        String accountId = created.getBody().get("id").toString();

        assertThat(call(
                                HttpMethod.PUT,
                                "/admin/tenants/globex/roles/editor",
                                token,
                                Map.of("permissions", List.of(Map.of("resource", "material", "action", "update"))),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);

        assertThat(call(
                                HttpMethod.PUT,
                                "/admin/accounts/" + accountId + "/roles",
                                token,
                                Map.of("roles", List.of("editor")),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.OK);

        assertThat(call(
                                HttpMethod.POST,
                                "/admin/accounts/" + accountId + "/identities",
                                token,
                                Map.of("issuer", "https://accounts.google.com", "subject", "12345"),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.CREATED);

        assertThat(identities.findByIssuerAndSubject("https://accounts.google.com", "12345"))
                .isPresent();
    }

    @Test
    void puttingARoleReplacesItsGrantsRatherThanAddingToThem() {
        String token = tokenFor(superuser());

        call(
                HttpMethod.PUT,
                "/admin/tenants/acme/roles/editor",
                token,
                Map.of(
                        "permissions",
                        List.of(
                                Map.of("resource", "material", "action", "read"),
                                Map.of("resource", "material", "action", "delete"))),
                String.class);
        call(
                HttpMethod.PUT,
                "/admin/tenants/acme/roles/editor",
                token,
                Map.of("permissions", List.of(Map.of("resource", "material", "action", "read"))),
                String.class);

        // A PATCH-like merge would have left `delete` behind, which is exactly the way a policy
        // accumulates a grant nobody remembers adding.
        Role role = roles.findByTenantIdAndName(acme.getId(), "editor").orElseThrow();
        assertThat(role.getPermissions())
                .extracting(PermissionEntry::asAuthority)
                .containsExactly("material:read");
    }

    @Test
    void aDuplicateIdentityLinkIsRefused() {
        String token = tokenFor(superuser());
        Account first = accountWith("first@example.test");
        Account second = accountWith("second@example.test");

        call(
                HttpMethod.POST,
                "/admin/accounts/" + first.getId() + "/identities",
                token,
                Map.of("issuer", "https://accounts.google.com", "subject", "shared"),
                String.class);

        // Re-pointing an established external identity at a different account would be a silent
        // account takeover, so it is refused rather than moved.
        assertThat(call(
                                HttpMethod.POST,
                                "/admin/accounts/" + second.getId() + "/identities",
                                token,
                                Map.of("issuer", "https://accounts.google.com", "subject", "shared"),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void aRoleFromAnotherTenantCannotBeAssigned() {
        String token = tokenFor(superuser());
        Tenant globex = tenants.saveAndFlush(new Tenant("globex", "Globex"));
        Role foreign = new Role(globex, "editor");
        foreign.setPermissions(List.of(new PermissionEntry("material", "update")));
        roles.saveAndFlush(foreign);
        Account account = accountWith("someone@example.test");

        // Roles are tenant-scoped. Assigning across tenants would let one customer's policy grant
        // access inside another's.
        assertThat(call(
                                HttpMethod.PUT,
                                "/admin/accounts/" + account.getId() + "/roles",
                                token,
                                Map.of("roles", List.of("editor")),
                                String.class)
                        .getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
