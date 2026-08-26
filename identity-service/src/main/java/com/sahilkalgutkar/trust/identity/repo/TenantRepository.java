package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.TenantEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface TenantRepository extends JpaRepository<TenantEntity, UUID> {

    Optional<TenantEntity> findBySlug(String slug);
}
