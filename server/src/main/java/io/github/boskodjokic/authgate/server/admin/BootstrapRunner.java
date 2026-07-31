package io.github.boskodjokic.authgate.server.admin;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Creates the first superuser, so a fresh deployment is not locked out of its own admin API.
 *
 * <p>The chicken-and-egg problem is real: every admin route requires a permission, permissions come
 * from an account, and accounts are created through the admin API. Something has to break the
 * cycle. The alternatives are worse — a default password, or an unauthenticated setup endpoint
 * that someone forgets to disable.
 *
 * <p>Two properties this deliberately has. It only acts on a database with no accounts at all, so
 * it cannot quietly re-grant superuser to an address an operator has since removed. And it creates
 * no credential: the bootstrap account signs in by magic link like anyone else, which means the
 * configuration value is an address rather than a secret, and is harmless in a shell history or a
 * deployment manifest.
 */
@Component
public class BootstrapRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapRunner.class);

    private final AuthGateProperties properties;
    private final TenantRepository tenants;
    private final AccountRepository accounts;

    public BootstrapRunner(AuthGateProperties properties, TenantRepository tenants, AccountRepository accounts) {
        this.properties = properties;
        this.tenants = tenants;
        this.accounts = accounts;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        AuthGateProperties.Bootstrap bootstrap = properties.bootstrap();
        if (bootstrap.email() == null || bootstrap.email().isBlank()) {
            return;
        }
        if (accounts.count() > 0) {
            // Not an error, and not worth a warning on every restart: the usual case is a healthy
            // deployment that was bootstrapped months ago and still has the property set.
            log.debug("Bootstrap skipped: accounts already exist");
            return;
        }

        Tenant tenant = tenants.findBySlug(bootstrap.tenant())
                .orElseGet(() -> tenants.save(new Tenant(bootstrap.tenant(), bootstrap.tenant())));

        Account account = new Account(tenant, bootstrap.email(), "Bootstrap superuser");
        account.grantSuperuser();
        accounts.save(account);

        log.warn(
                "Bootstrapped superuser {} in tenant '{}'. Sign in with a magic link, create your own "
                        + "accounts, then remove authgate.bootstrap.email.",
                account.getEmail(),
                tenant.getSlug());
    }
}
