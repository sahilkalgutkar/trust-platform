package com.sahilkalgutkar.trust.authz.audit;

import com.sahilkalgutkar.trust.authz.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.authz.repo.AuditOutboxRepository;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Writes audit events into the transactional outbox, in the same transaction as the tuple change
 * they describe.
 *
 * <p>Note what is <em>not</em> audited here: individual checks. A busy authorization service answers
 * millions of them, and an audit log of every read would drown the record of the writes that
 * actually changed who can do what. Grants and revocations are the security-relevant events; the
 * check volume belongs in metrics.
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
