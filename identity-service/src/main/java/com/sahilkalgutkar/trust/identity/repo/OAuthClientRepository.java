package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface OAuthClientRepository extends JpaRepository<OAuthClientEntity, UUID> {

    Optional<OAuthClientEntity> findByClientId(String clientId);
}
