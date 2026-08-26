package com.sahilkalgutkar.trust.authz.repo;

import com.sahilkalgutkar.trust.authz.domain.NamespaceEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface NamespaceRepository extends JpaRepository<NamespaceEntity, NamespaceEntity.Key> {

    Optional<NamespaceEntity> findByTenantIdAndName(UUID tenantId, String name);

    List<NamespaceEntity> findByTenantId(UUID tenantId);
}
