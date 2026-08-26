package com.sahilkalgutkar.trust.audit.chain;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import com.sahilkalgutkar.trust.common.hash.HashChain;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/**
 * Appends events to a tenant's hash chain.
 *
 * <p>Appending is strictly serial per tenant, which is why the Kafka topic is keyed by tenant: one
 * partition, one consumer thread, one chain being extended at a time. The unique constraint on
 * {@code (tenant_id, seq)} is the backstop for when that assumption is violated anyway — a rebalance,
 * a second instance, an operator replaying a topic. Losing the insert is the correct outcome there;
 * two records claiming the same position would fork the chain and make verification meaningless.
 */
@Service
public class AuditChainService {

    private final AuditEventRepository repository;
    private final Clock clock;

    public AuditChainService(AuditEventRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    @Transactional
    public AppendResult append(AuditEvent event) {
        UUID tenantId = UUID.fromString(event.tenantId());

        Optional<AuditEventEntity> head = repository.findFirstByTenantIdOrderBySeqDesc(tenantId);
        if (repository.existsByTenantIdAndEventId(tenantId, event.eventId())) {
            return new AppendResult(AppendResult.Outcome.DUPLICATE,
                    head.map(AuditEventEntity::getSeq).orElse(0L),
                    head.map(AuditEventEntity::getHash).orElse(HashChain.GENESIS));
        }

        String prevHash = head.map(AuditEventEntity::getHash).orElse(HashChain.GENESIS);
        long seq = head.map(AuditEventEntity::getSeq).orElse(0L) + 1;

        // Hash over this service's own canonicalization rather than the producer's raw bytes: two
        // services that both use CanonicalJson produce identical bytes for an identical event, so
        // this changes nothing in the normal case — but it means a producer cannot smuggle in
        // semantically-equal-but-differently-encoded JSON that verification would then reject.
        String payload = CanonicalJson.string(event);
        String hash = HashChain.link(prevHash, payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        repository.save(new AuditEventEntity(UUID.randomUUID(), tenantId, seq, event.eventId(),
                event.actor(), event.action(), event.resourceType(), event.resourceId(),
                event.outcome(), event.occurredAt(), payload, prevHash, hash, clock.instant()));

        return new AppendResult(AppendResult.Outcome.APPENDED, seq, hash);
    }

    @Transactional(readOnly = true)
    public ChainHead head(UUID tenantId) {
        return repository.findFirstByTenantIdOrderBySeqDesc(tenantId)
                .map(entity -> new ChainHead(entity.getSeq(), entity.getHash(), entity.getRecordedAt()))
                .orElse(new ChainHead(0, HashChain.GENESIS, null));
    }
}
