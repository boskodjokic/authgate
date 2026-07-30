package io.github.boskodjokic.authgate.server.account;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccountRepository extends JpaRepository<Account, UUID> {

    /**
     * Used by the magic-link flow, which starts from an address rather than a token. Scoped to a
     * tenant because the address is only unique within one.
     */
    Optional<Account> findByTenantIdAndEmail(UUID tenantId, String email);
}
