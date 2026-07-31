package io.github.boskodjokic.authgate.server.token;

import java.time.Instant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface RevokedTokenRepository extends JpaRepository<RevokedToken, String> {

    boolean existsByJti(String jti);

    /** Drops entries for tokens that have expired on their own, so the table stays bounded. */
    @Modifying
    @Transactional
    @Query("delete from RevokedToken token where token.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}
