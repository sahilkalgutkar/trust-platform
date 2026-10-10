package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    List<RefreshTokenEntity> findAllByFamilyId(UUID familyId);

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
}
