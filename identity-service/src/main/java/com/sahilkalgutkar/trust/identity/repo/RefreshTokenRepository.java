package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /**
     * Consumes the token if nothing has consumed or revoked it yet, and says whether it did. Two
     * refreshes can both read the token as unused, so the read cannot decide which one wins; this
     * can, because the database checks the condition again once a concurrent consumption commits.
     *
     * @return 1 if this call consumed the token, 0 if it was already used
     */
    @Modifying
    @Query("update RefreshTokenEntity t set t.consumedAt = :at "
            + "where t.id = :id and t.consumedAt is null and t.revokedAt is null")
    int consumeIfUnused(@Param("id") UUID id, @Param("at") Instant at);

    /**
     * Revokes the family's tokens that are not revoked yet, setting nothing but {@code revoked_at},
     * and says how many there were. One pass cannot see a token that a rotation still in flight
     * has issued; {@code CompromiseResponder.revokeFamily} runs it until it finds none.
     *
     * @return how many tokens this pass revoked
     */
    @Modifying
    @Query("update RefreshTokenEntity t set t.revokedAt = :at where t.familyId = :family and t.revokedAt is null")
    int revokeUnrevoked(@Param("family") UUID familyId, @Param("at") Instant at);
}
