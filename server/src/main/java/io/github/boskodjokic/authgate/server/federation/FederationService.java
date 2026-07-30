package io.github.boskodjokic.authgate.server.federation;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.FederatedIdentity;
import io.github.boskodjokic.authgate.server.account.FederatedIdentityRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import io.github.boskodjokic.authgate.server.config.AuthGateProperties;
import io.github.boskodjokic.authgate.server.token.AccessTokenIssuer;
import io.github.boskodjokic.authgate.server.token.IssuedToken;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Exchanges a provider's token for one of ours. */
@Service
public class FederationService {

    private static final Logger log = LoggerFactory.getLogger(FederationService.class);

    private final ProviderRegistry registry;
    private final FederatedIdentityRepository identities;
    private final AccountRepository accounts;
    private final TenantRepository tenants;
    private final AccessTokenIssuer issuer;
    private final AuthGateProperties properties;

    public FederationService(
            ProviderRegistry registry,
            FederatedIdentityRepository identities,
            AccountRepository accounts,
            TenantRepository tenants,
            AccessTokenIssuer issuer,
            AuthGateProperties properties) {
        this.registry = registry;
        this.identities = identities;
        this.accounts = accounts;
        this.tenants = tenants;
        this.issuer = issuer;
        this.properties = properties;
    }

    /**
     * Verifies a provider token and issues a local access token for the linked account.
     *
     * @throws FederationException if the token is invalid or no account is linked
     */
    @Transactional
    public IssuedToken exchange(String providerToken) {
        if (providerToken == null || providerToken.isBlank()) {
            throw new FederationException("token must not be blank");
        }
        Principal principal = registry.authenticate(providerToken);

        Account account = identities
                .findByIssuerAndSubject(principal.issuer(), principal.subject())
                .map(FederatedIdentity::getAccount)
                .or(() -> linkOnFirstSignIn(principal))
                .orElseThrow(() -> new FederationException(
                        "no account is linked to " + principal.provider() + " subject " + principal.subject()));

        if (!account.isActive()) {
            throw new FederationException("account is not active");
        }
        return issuer.issue(account, properties.federation().audience());
    }

    /**
     * Attaches a first-time federated sign-in to an existing account with the same address.
     *
     * <p>Off unless the provider opts in, and this is the single most dangerous switch in the
     * service. Enabling it means trusting a provider's claim about an address it may not own:
     * anyone who can make that IdP assert {@code alice@example.com} can reach Alice's account. It
     * is safe only where the provider is authoritative for the domain — a corporate Entra or Okta
     * tenant — and never for a consumer IdP that will assert whatever address someone signed up
     * with.
     */
    private Optional<Account> linkOnFirstSignIn(Principal principal) {
        FederatedProviderProperties config = configFor(principal);
        if (!config.linkByVerifiedEmail()) {
            return Optional.empty();
        }
        if (principal.email() == null || !principal.emailVerified()) {
            log.info("{}: refusing to link, address is absent or unverified", principal.provider());
            return Optional.empty();
        }

        Optional<Account> account = tenants.findBySlug(config.tenant())
                .filter(Tenant::isActive)
                .flatMap(tenant -> accounts.findByTenantIdAndEmail(tenant.getId(), principal.email()));

        account.ifPresent(found -> {
            identities.save(new FederatedIdentity(found, principal.issuer(), principal.subject()));
            log.info(
                    "{}: linked subject {} to existing account in tenant {}",
                    principal.provider(),
                    principal.subject(),
                    config.tenant());
        });
        return account;
    }

    private FederatedProviderProperties configFor(Principal principal) {
        return properties.federation().providers().stream()
                .filter(candidate -> candidate.name().equals(principal.provider()))
                .findFirst()
                .orElseThrow(() -> new FederationException("unknown provider " + principal.provider()));
    }
}
