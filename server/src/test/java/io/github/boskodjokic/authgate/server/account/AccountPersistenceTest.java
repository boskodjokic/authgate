package io.github.boskodjokic.authgate.server.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Exercises the constraints that carry security meaning, against a real Postgres.
 *
 * <p>Skips without a container runtime; see {@link
 * io.github.boskodjokic.authgate.server.AuthGateApplicationTests}.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Testcontainers(disabledWithoutDocker = true)
class AccountPersistenceTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TenantRepository tenants;

    @Autowired
    private AccountRepository accounts;

    @Autowired
    private FederatedIdentityRepository identities;

    private Tenant acme;

    @BeforeEach
    void setUp() {
        acme = tenants.saveAndFlush(new Tenant("acme", "Acme"));
    }

    @Test
    void anAccountIsReachableByTenantAndEmail() {
        accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));

        assertThat(accounts.findByTenantIdAndEmail(acme.getId(), "bosko@example.test"))
                .isPresent();
    }

    @Test
    void theSameAddressMayExistInTwoTenants() {
        Tenant other = tenants.saveAndFlush(new Tenant("globex", "Globex"));

        accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
        accounts.saveAndFlush(new Account(other, "bosko@example.test", "Bosko"));

        // Uniqueness is per tenant. If it were global, the first customer to sign up would own
        // that address everywhere and block every later one.
        assertThat(accounts.findAll()).hasSize(2);
    }

    @Test
    void theSameAddressCannotBeDuplicatedWithinOneTenant() {
        accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));

        assertThatThrownBy(() -> accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Impostor")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void addressesAreNormalisedSoCaseCannotForkAnAccount() {
        accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));

        // Without normalisation this would insert a second row and a magic link sent to the
        // address would become ambiguous.
        assertThatThrownBy(() -> accounts.saveAndFlush(new Account(acme, "  BOSKO@Example.TEST ", "Impostor")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void aFederatedIdentityIsReachableByIssuerAndSubject() {
        Account account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));
        identities.saveAndFlush(
                new FederatedIdentity(account, "https://accounts.google.com", "10769150350006150715113082367"));

        assertThat(identities.findByIssuerAndSubject("https://accounts.google.com", "10769150350006150715113082367"))
                .isPresent()
                .get()
                .extracting(found -> found.getAccount().getId())
                .isEqualTo(account.getId());
    }

    @Test
    void oneIssuerAndSubjectPairCannotPointAtTwoAccounts() {
        Account first = accounts.saveAndFlush(new Account(acme, "first@example.test", "First"));
        Account second = accounts.saveAndFlush(new Account(acme, "second@example.test", "Second"));
        identities.saveAndFlush(new FederatedIdentity(first, "https://accounts.google.com", "shared-subject"));

        // This constraint is the whole reason the table exists. Without it, a second row could
        // silently redirect an established external identity at a different local account.
        assertThatThrownBy(() -> identities.saveAndFlush(
                        new FederatedIdentity(second, "https://accounts.google.com", "shared-subject")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void theSameSubjectFromADifferentIssuerIsADifferentIdentity() {
        Account account = accounts.saveAndFlush(new Account(acme, "bosko@example.test", "Bosko"));

        identities.saveAndFlush(new FederatedIdentity(account, "https://accounts.google.com", "12345"));
        identities.saveAndFlush(new FederatedIdentity(account, "https://login.microsoftonline.com/t/v2.0", "12345"));

        // Subjects are only unique within an issuer, so the pair is what must be unique — not the
        // subject on its own.
        assertThat(identities.findAll()).hasSize(2);
    }
}
