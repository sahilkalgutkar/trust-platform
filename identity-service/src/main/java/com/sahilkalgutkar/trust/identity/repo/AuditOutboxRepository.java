package com.sahilkalgutkar.trust.identity.repo;

import com.sahilkalgutkar.trust.identity.domain.AuditOutboxEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface AuditOutboxRepository extends JpaRepository<AuditOutboxEntity, UUID> {

    List<AuditOutboxEntity> findTop200ByPublishedAtIsNullOrderByCreatedAtAsc();
}
