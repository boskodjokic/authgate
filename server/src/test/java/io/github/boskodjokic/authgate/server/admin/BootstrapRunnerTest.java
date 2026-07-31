package io.github.boskodjokic.authgate.server.admin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/** The escape from the chicken-and-egg problem: a protected admin API on an empty database. */
@SpringBootTest
@Testcontainers(disabledWithoutDocker = true)
class BootstrapRunnerTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void bootstrapConfiguration(DynamicPropertyRegistry registry) {
        registry.add("authgate.bootstrap.tenant", () -> "founding");
        registry.add("authgate.bootstrap.email", () -> "root@example.test");
    }

    @Autowired
    private BootstrapRunner runner;

    @Autowired
    private AccountRepository accounts;

    @Autowired
    private TenantRepository tenants;

    private static final ApplicationArguments NO_ARGS = new DefaultApplicationArguments();

    @Test
    void theRunnerCreatedASuperuserOnAnEmptyDatabase() {
        // Already executed during context startup.
        Account root = accounts.findAll().stream()
                .filter(account -> account.getEmail().equals("root@example.test"))
                .findFirst()
                .orElseThrow();

        assertThat(root.isSuperuser()).isTrue();
        // Compared by id rather than by reading through the lazy association: Tenant is a proxy
        // outside a transaction, and getSlug() would initialise it where getId() does not.
        assertThat(tenants.findBySlug("founding"))
                .isPresent()
                .get()
                .extracting(Tenant::getId)
                .isEqualTo(root.getTenant().getId());
    }

    @Test
    void theBootstrapAccountHasNoCredential() {
        // There is nothing to leak and nothing to rotate: the bootstrap address signs in by magic
        // link like every other account. That is what makes it safe to put in a deployment
        // manifest.
        Account root = accounts.findAll().stream()
                .filter(account -> account.getEmail().equals("root@example.test"))
                .findFirst()
                .orElseThrow();

        assertThat(root.getRoles()).isEmpty();
        assertThat(root.isActive()).isTrue();
    }

    @Test
    void runningAgainDoesNothingOnceAccountsExist() {
        long before = accounts.count();

        runner.run(NO_ARGS);

        // Guarding on "no accounts at all" rather than "this address is missing" is deliberate:
        // otherwise removing the bootstrap account would silently recreate it on the next deploy,
        // handing superuser back to an address an operator had chosen to delete.
        assertThat(accounts.count()).isEqualTo(before);
    }
}
