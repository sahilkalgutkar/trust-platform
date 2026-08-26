package com.sahilkalgutkar.trust.audit.repo;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, UUID> {

    /** The current head of a tenant's chain — what the next record chains from. */
    Optional<AuditEventEntity> findFirstByTenantIdOrderBySeqDesc(UUID tenantId);

    boolean existsByTenantIdAndEventId(UUID tenantId, String eventId);

    /** Ascending, because verification has to walk the chain in the order it was built. */
    List<AuditEventEntity> findByTenantIdAndSeqGreaterThanOrderBySeqAsc(UUID tenantId, long afterSeq,
                                                                        Limit limit);

    List<AuditEventEntity> findByTenantIdOrderBySeqDesc(UUID tenantId, Limit limit);

    long countByTenantId(UUID tenantId);
}
