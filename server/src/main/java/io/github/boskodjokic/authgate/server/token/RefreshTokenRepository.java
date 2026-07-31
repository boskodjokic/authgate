package io.github.boskodjokic.authgate.server.token;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Marks a token spent, and reports whether this call is the one that did it.
     *
     * <p>Rotation has to be decided by the database. Two requests presenting the same token at once
     * would both read an unconsumed row and both mint a replacement, which is a session silently
     * forking in two. A conditional UPDATE means exactly one caller sees a row count of 1.
     *
     * @return 1 if this call consumed the token, 0 if it was already spent, revoked or expired
     */
    @Modifying
    @Query(
            """
            update RefreshToken token
               set token.consumedAt = :now
             where token.tokenHash = :tokenHash
               and token.consumedAt is null
               and token.revokedAt is null
               and token.expiresAt > :now
            """)
    int consume(@Param("tokenHash") String tokenHash, @Param("now") Instant now);

    /** Withdraws every member of a family at once — logout, or a detected replay. */
    @Modifying
    @Query(
            """
            update RefreshToken token
               set token.revokedAt = :now
             where token.familyId = :familyId
               and token.revokedAt is null
            """)
    int revokeFamily(@Param("familyId") UUID familyId, @Param("now") Instant now);

    long countByFamilyId(UUID familyId);
}
