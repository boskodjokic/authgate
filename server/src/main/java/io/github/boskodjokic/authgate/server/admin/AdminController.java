package io.github.boskodjokic.authgate.server.admin;

import io.github.boskodjokic.authgate.server.account.Account;
import io.github.boskodjokic.authgate.server.account.AccountRepository;
import io.github.boskodjokic.authgate.server.account.FederatedIdentity;
import io.github.boskodjokic.authgate.server.account.FederatedIdentityRepository;
import io.github.boskodjokic.authgate.server.account.PermissionEntry;
import io.github.boskodjokic.authgate.server.account.Role;
import io.github.boskodjokic.authgate.server.account.RoleRepository;
import io.github.boskodjokic.authgate.server.account.Tenant;
import io.github.boskodjokic.authgate.server.account.TenantRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Administration of tenants, accounts, roles and identity links.
 *
 * <p>Every method is gated by the same {@code resource:action} model the service issues to
 * everyone else — there is no separate admin mechanism, and no back door that exists only for
 * this controller. {@code superuser} is accepted alongside each specific permission rather than
 * bypassing the check invisibly, so reading any single method tells you exactly who may call it.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final TenantRepository tenants;
    private final AccountRepository accounts;
    private final RoleRepository roles;
    private final FederatedIdentityRepository identities;

    public AdminController(
            TenantRepository tenants,
            AccountRepository accounts,
            RoleRepository roles,
            FederatedIdentityRepository identities) {
        this.tenants = tenants;
        this.accounts = accounts;
        this.roles = roles;
        this.identities = identities;
    }

    // -- tenants -----------------------------------------------------------

    @GetMapping("/tenants")
    @PreAuthorize("hasAnyAuthority('superuser', 'tenant:read')")
    public List<TenantView> listTenants() {
        return tenants.findAll().stream().map(TenantView::of).toList();
    }

    @PostMapping("/tenants")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyAuthority('superuser', 'tenant:write')")
    public TenantView createTenant(@Valid @RequestBody CreateTenant body) {
        tenants.findBySlug(body.slug()).ifPresent(existing -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "slug is already taken");
        });
        return TenantView.of(tenants.save(new Tenant(body.slug(), body.name())));
    }

    // -- accounts ----------------------------------------------------------

    @GetMapping("/tenants/{slug}/accounts")
    @PreAuthorize("hasAnyAuthority('superuser', 'account:read')")
    public List<AccountView> listAccounts(@PathVariable String slug) {
        Tenant tenant = tenant(slug);
        return accounts.findAll().stream()
                .filter(account -> account.getTenant().getId().equals(tenant.getId()))
                .map(AccountView::of)
                .toList();
    }

    @PostMapping("/tenants/{slug}/accounts")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyAuthority('superuser', 'account:write')")
    public AccountView createAccount(@PathVariable String slug, @Valid @RequestBody CreateAccount body) {
        Tenant tenant = tenant(slug);
        accounts.findByTenantIdAndEmail(tenant.getId(), Account.normalizeEmail(body.email()))
                .ifPresent(existing -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "address already has an account");
                });
        return AccountView.of(accounts.save(new Account(tenant, body.email(), body.displayName())));
    }

    // -- roles -------------------------------------------------------------

    @GetMapping("/tenants/{slug}/roles")
    @PreAuthorize("hasAnyAuthority('superuser', 'role:read')")
    public List<RoleView> listRoles(@PathVariable String slug) {
        return roles.findByTenantId(tenant(slug).getId()).stream()
                .map(RoleView::of)
                .toList();
    }

    /**
     * Creates or replaces a role.
     *
     * <p>A PUT that replaces the whole grant set, not a PATCH that adds one. Incremental
     * permission edits are how a policy ends up holding a grant nobody remembers adding; stating
     * the intended set in full means the request is also a readable record of it.
     */
    @PutMapping("/tenants/{slug}/roles/{name}")
    @PreAuthorize("hasAnyAuthority('superuser', 'role:write')")
    @Transactional
    public RoleView putRole(@PathVariable String slug, @PathVariable String name, @Valid @RequestBody PutRole body) {
        Tenant tenant = tenant(slug);
        Role role = roles.findByTenantIdAndName(tenant.getId(), name).orElseGet(() -> new Role(tenant, name));
        role.setPermissions(body.permissions().stream()
                .map(grant -> new PermissionEntry(grant.resource(), grant.action()))
                .toList());
        return RoleView.of(roles.save(role));
    }

    @PutMapping("/accounts/{accountId}/roles")
    @PreAuthorize("hasAnyAuthority('superuser', 'account:write')")
    @Transactional
    public AccountView assignRoles(@PathVariable UUID accountId, @Valid @RequestBody AssignRoles body) {
        Account account = accounts.findById(accountId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such account"));

        List<Role> assigned = body.roles().stream()
                .map(name -> roles.findByTenantIdAndName(account.getTenant().getId(), name)
                        .orElseThrow(
                                () -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "no such role: " + name)))
                .toList();

        account.setRoles(assigned);
        return AccountView.of(accounts.save(account));
    }

    // -- federated identity links -------------------------------------------

    /**
     * Links an external identity to an account.
     *
     * <p>This is the safe counterpart to {@code link-by-verified-email}: an operator states the
     * {@code (issuer, subject)} pair explicitly, rather than the service inferring it from an
     * address a provider happened to assert.
     */
    @PostMapping("/accounts/{accountId}/identities")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyAuthority('superuser', 'account:write')")
    public IdentityView linkIdentity(@PathVariable UUID accountId, @Valid @RequestBody LinkIdentity body) {
        Account account = accounts.findById(accountId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such account"));

        identities.findByIssuerAndSubject(body.issuer(), body.subject()).ifPresent(existing -> {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "that issuer and subject are already linked to an account");
        });
        return IdentityView.of(identities.save(new FederatedIdentity(account, body.issuer(), body.subject())));
    }

    private Tenant tenant(String slug) {
        return tenants.findBySlug(slug)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "no such tenant"));
    }

    // -- request and response shapes ----------------------------------------

    /**
     * A new tenant.
     *
     * @param slug url-safe identifier
     * @param name human-readable name
     */
    public record CreateTenant(@NotBlank String slug, @NotBlank String name) {}

    /**
     * A new account.
     *
     * @param email the address
     * @param displayName optional label
     */
    public record CreateAccount(@NotBlank @Email String email, String displayName) {}

    /**
     * A single grant.
     *
     * @param resource what is being acted on
     * @param action what may be done to it
     */
    public record Grant(@NotBlank String resource, @NotBlank String action) {}

    /**
     * The full definition of a role.
     *
     * @param permissions the complete grant set, which replaces whatever was there before
     */
    public record PutRole(@NotEmpty List<@Valid Grant> permissions) {}

    /**
     * A role assignment.
     *
     * @param roles the complete set of role names, which replaces the current assignment
     */
    public record AssignRoles(List<String> roles) {}

    /**
     * An external identity to attach to an account.
     *
     * @param issuer the provider's {@code iss} value
     * @param subject the provider's stable subject
     */
    public record LinkIdentity(@NotBlank String issuer, @NotBlank String subject) {}

    /**
     * A tenant as returned to a caller.
     *
     * @param id surrogate key
     * @param slug url-safe identifier
     * @param name human-readable name
     * @param active whether it may be used
     */
    public record TenantView(UUID id, String slug, String name, boolean active) {
        static TenantView of(Tenant tenant) {
            return new TenantView(tenant.getId(), tenant.getSlug(), tenant.getName(), tenant.isActive());
        }
    }

    /**
     * An account as returned to a caller.
     *
     * @param id surrogate key
     * @param email address
     * @param displayName human-readable label
     * @param active whether it may sign in
     * @param superuser whether every permission check passes for this account
     * @param roles assigned role names
     */
    public record AccountView(
            UUID id, String email, String displayName, boolean active, boolean superuser, Set<String> roles) {
        static AccountView of(Account account) {
            return new AccountView(
                    account.getId(),
                    account.getEmail(),
                    account.getDisplayName(),
                    account.isActive(),
                    account.isSuperuser(),
                    account.getRoles().stream().map(Role::getName).collect(java.util.stream.Collectors.toSet()));
        }
    }

    /**
     * A role as returned to a caller.
     *
     * @param name the role name
     * @param permissions its grants, grouped as {@code resource -> actions}
     */
    public record RoleView(String name, Map<String, Set<String>> permissions) {
        static RoleView of(Role role) {
            Map<String, Set<String>> grouped = new java.util.TreeMap<>();
            role.getPermissions()
                    .forEach(entry -> grouped.computeIfAbsent(entry.getResource(), key -> new java.util.TreeSet<>())
                            .add(entry.getAction()));
            return new RoleView(role.getName(), grouped);
        }
    }

    /**
     * A federated identity link as returned to a caller.
     *
     * @param issuer the provider's {@code iss} value
     * @param subject the provider's stable subject
     * @param accountId the account it points at
     */
    public record IdentityView(String issuer, String subject, UUID accountId) {
        static IdentityView of(FederatedIdentity identity) {
            return new IdentityView(
                    identity.getIssuer(),
                    identity.getSubject(),
                    identity.getAccount().getId());
        }
    }
}
