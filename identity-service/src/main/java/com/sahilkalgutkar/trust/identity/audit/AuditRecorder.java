package com.sahilkalgutkar.trust.identity.audit;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import com.sahilkalgutkar.trust.identity.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.identity.repo.AuditOutboxRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Writes audit events into the transactional outbox.
 *
 * <p>Deliberately not a Kafka call. Publishing inline would create two failure modes with no good
 * answer: publish before commit and a rolled-back transaction leaves an audit record for something
 * that never happened; publish after commit and a broker outage silently drops the record for
 * something that did. Writing to a table in the same transaction as the thing being audited makes
 * the record exactly as durable as the event itself, and turns a Kafka outage into latency instead
 * of loss.
 *
 * <p>{@code MANDATORY} enforces that at compile-run time: calling this outside a transaction is a
 * bug, and it fails loudly rather than quietly writing its own.
 */
@Component
public class AuditRecorder {

    private final AuditOutboxRepository outboxRepository;

    public AuditRecorder(AuditOutboxRepository outboxRepository) {
        this.outboxRepository = outboxRepository;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEvent event) {
        outboxRepository.save(new AuditOutboxEntity(
                UUID.randomUUID(),
                UUID.fromString(event.tenantId()),
                CanonicalJson.string(event)));
    }
}
