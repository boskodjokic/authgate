package io.github.boskodjokic.authgate.server.account;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentity, UUID> {

    /** The only supported lookup for a federated token. See {@link FederatedIdentity}. */
    Optional<FederatedIdentity> findByIssuerAndSubject(String issuer, String subject);
}
