package io.github.boskodjokic.authgate.server.magiclink;

import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MagicLinkRepository extends JpaRepository<MagicLink, String> {

    /**
     * Marks a link consumed, and reports whether this call is the one that did it.
     *
     * <p>Single-use has to be decided by the database, not by read-then-write in the service: two
     * requests arriving together would both observe an unconsumed row and both mint a token. A
     * conditional UPDATE settles it — exactly one caller sees a row count of 1, whatever the
     * isolation level.
     *
     * @return 1 if this call consumed the link, 0 if it was already used, expired or absent
     */
    @Modifying
    @Query(
            """
            update MagicLink link
               set link.consumedAt = :now
             where link.tokenHash = :tokenHash
               and link.consumedAt is null
               and link.expiresAt > :now
            """)
    int consume(@Param("tokenHash") String tokenHash, @Param("now") Instant now);

    Optional<MagicLink> findByTokenHash(String tokenHash);
}
