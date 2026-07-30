package io.github.boskodjokic.authgate.server.federation;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.FederatedIdentity;
import io.github.boskodjokic.authgate.server.account.FederatedIdentityRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * First-sign-in linking, with {@code link-by-verified-email} switched on.
 *
 * <p>Kept apart from {@link FederationExchangeTest} because it is a different security posture,
 * not a different case: with this on, the service trusts a provider's word about an address. These
 * tests pin down exactly how far that trust extends.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers(disabledWithoutDocker = true)
class FederationLinkingTest {

    private static final String AUDIENCE = "authgate-client-id";

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    static final FakeIdp IDP;

    static {
        try {
            IDP = new FakeIdp();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @DynamicPropertySource
    static void providerConfiguration(DynamicPropertyRegistry registry) {
        registry.add("authgate.federation.audience", () -> "http://localhost:8080");
        registry.add("authgate.federation.providers[0].name", () -> "corporate");
        registry.add("authgate.federation.providers[0].issuer", IDP::issuer);
        registry.add("authgate.federation.providers[0].audience", () -> AUDIENCE);
        registry.add("authgate.federation.providers[0].tenant", () -> "acme");
        registry.add("authgate.federation.providers[0].link-by-verified-email", () -> "true");
    }

    @AfterAll
    static void stopIdp() {
        IDP.close();
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
    private FederatedIdentityRepository identities;

    private Account account;

    @BeforeEach
    void setUp() {
        identities.deleteAll();
        accounts.deleteAll();
        tenants.deleteAll();

        Tenant acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
        account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> exchange(String token) {
        return restTemplate.postForEntity(
                "http://localhost:" + port + "/auth/federated/exchange",
                Map.of("token", token),
                (Class<Map<String, Object>>) (Class<?>) Map.class);
    }

    @Test
    void aVerifiedAddressLinksToTheExistingAccount() {
        ResponseEntity<Map<String, Object>> response =
                exchange(IDP.validToken(AUDIENCE, "subject-1", "bosko@example.test", true));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(identities.findByIssuerAndSubject(IDP.issuer(), "subject-1"))
                .isPresent()
                .get()
                .extracting(identity -> identity.getAccount().getId())
                .isEqualTo(account.getId());
    }

    @Test
    void theLinkIsMadeOnceAndReusedAfterwards() {
        exchange(IDP.validToken(AUDIENCE, "subject-1", "bosko@example.test", true));
        exchange(IDP.validToken(AUDIENCE, "subject-1", "bosko@example.test", true));

        // A second sign-in must find the existing row rather than insert another. The unique
        // constraint would reject it anyway; this asserts we never get that far.
        assertThat(identities.findAll()).hasSize(1);
    }

    @Test
    void anUnverifiedAddressDoesNotLink() {
        // The provider says who they are but will not vouch for the address. Linking on that would
        // let anyone who can set an unverified address on an IdP account claim someone else's.
        assertThat(exchange(IDP.validToken(AUDIENCE, "subject-1", "bosko@example.test", false))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(identities.findAll()).isEmpty();
    }

    @Test
    void anAddressWithNoMatchingAccountDoesNotProvisionOne() {
        // Linking attaches a provider identity to an account that already exists. It is not
        // just-in-time provisioning, and must never conjure an account from a token alone.
        assertThat(exchange(IDP.validToken(AUDIENCE, "subject-1", "stranger@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(accounts.findAll()).hasSize(1);
        assertThat(identities.findAll()).isEmpty();
    }

    @Test
    void linkingIsConfinedToTheProvidersOwnTenant() {
        Tenant other = tenants.saveAndFlush(new Tenant("globex", "Globex"));
        accounts.saveAndFlush(new Account(other, "elsewhere@example.test", "Elsewhere"));

        // The provider is configured for acme, so an address that only exists in globex is out of
        // reach. Otherwise configuring an IdP for one tenant would give it a way into every other.
        assertThat(exchange(IDP.validToken(AUDIENCE, "subject-1", "elsewhere@example.test", true))
                        .getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(identities.findAll()).isEmpty();
    }

    @Test
    void anExistingLinkStillWinsOverTheAddress() {
        Account second = accounts.saveAndFlush(
                new Account(tenants.findBySlug("acme").orElseThrow(), "second@example.test", "Second"));
        identities.saveAndFlush(new FederatedIdentity(second, IDP.issuer(), "subject-1"));

        // Subject is already linked to `second`, but the token asserts the address of `account`.
        // The link must decide, not the address — otherwise a provider could move a session
        // between accounts just by changing what it asserts.
        ResponseEntity<Map<String, Object>> response =
                exchange(IDP.validToken(AUDIENCE, "subject-1", "bosko@example.test", true));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(identities.findAll()).hasSize(1);
        assertThat(identities.findByIssuerAndSubject(IDP.issuer(), "subject-1"))
                .get()
                .extracting(identity -> identity.getAccount().getId())
                .isEqualTo(second.getId());
    }
}
