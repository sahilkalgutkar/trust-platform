package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCodeEntity, UUID> {

    Optional<AuthorizationCodeEntity> findByCodeHash(String codeHash);

    /**
     * Consumes the code if no other exchange has, for the same reason as
     * {@link RefreshTokenRepository#consumeIfUnused}.
     *
     * @return 1 if this call consumed the code, 0 if it was already used
     */
    @Modifying
    @Query("update AuthorizationCodeEntity c set c.consumedAt = :at where c.id = :id and c.consumedAt is null")
    int consumeIfUnused(@Param("id") UUID id, @Param("at") Instant at);
}
