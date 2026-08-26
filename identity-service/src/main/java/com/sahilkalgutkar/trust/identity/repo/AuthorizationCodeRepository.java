package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCodeEntity, UUID> {

    Optional<AuthorizationCodeEntity> findByCodeHash(String codeHash);
}
