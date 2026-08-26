package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.audit.AuditRecorder;
import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.UnknownRelationException;
import com.sahilkalgutkar.trust.authz.model.Zookie;
import com.sahilkalgutkar.trust.authz.repo.RelationTupleRepository;
import com.sahilkalgutkar.trust.authz.repo.RevisionSequence;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.UUID;

/**
 * Applies a batch of relationship changes atomically and returns the revision they landed at.
 *
 * <p>The batch is one transaction and one revision on purpose. Permission changes usually come in
 * pairs that are only correct together — remove Ada as an editor, add her as a viewer — and applying
 * them at separate revisions creates a window where she is neither, or worse, both. One revision
 * also means one zookie: the caller gets back a single token that provably includes the whole
 * change, which is what it needs to avoid reading its own write back stale.
 */
@Service
public class TupleWriter {

    private final RelationTupleRepository tupleRepository;
    private final NamespaceCatalog namespaceCatalog;
    private final RevisionSequence revisionSequence;
    private final AuditRecorder auditRecorder;
    private final Clock clock;

    public TupleWriter(RelationTupleRepository tupleRepository, NamespaceCatalog namespaceCatalog,
                       RevisionSequence revisionSequence, AuditRecorder auditRecorder, Clock clock) {
        this.tupleRepository = tupleRepository;
        this.namespaceCatalog = namespaceCatalog;
        this.revisionSequence = revisionSequence;
        this.auditRecorder = auditRecorder;
        this.clock = clock;
    }

    @Transactional
    public Zookie apply(UUID tenantId, String actor, List<TupleChange> changes) {
        if (changes == null || changes.isEmpty()) {
            throw new IllegalArgumentException("At least one change is required");
        }
        changes.forEach(change -> requireDefinedRelation(tenantId, change));

        long revision = revisionSequence.next();
        changes.forEach(change -> {
            switch (change.operation()) {
                case WRITE -> write(change, revision);
                case DELETE -> delete(change);
            }
            auditRecorder.record(AuditEvent.builder(tenantId.toString(),
                            "tuple." + change.operation().name().toLowerCase())
                    .actor(actor)
                    .resource(change.namespace(), change.objectId())
                    .attribute("relation", change.relation())
                    .attribute("subject", change.subject().toString())
                    .attribute("revision", Long.toString(revision))
                    .occurredAt(clock.instant())
                    .build());
        });
        return Zookie.of(revision);
    }

    private void write(TupleChange change, long revision) {
        // Idempotent: writing a relationship that already exists is a no-op rather than a duplicate
        // row or an error, because a client retrying after a timeout should not have to know which.
        boolean exists = tupleRepository
                .findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
                        change.namespace(), change.objectId(), change.relation(),
                        change.subject().type(), change.subject().id(), change.subject().relation())
                .isPresent();
        if (!exists) {
            tupleRepository.save(new RelationTupleEntity(UUID.randomUUID(), change.namespace(),
                    change.objectId(), change.relation(), change.subject(), revision));
        }
    }

    private void delete(TupleChange change) {
        tupleRepository
                .findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
                        change.namespace(), change.objectId(), change.relation(),
                        change.subject().type(), change.subject().id(), change.subject().relation())
                .ifPresent(tupleRepository::delete);
    }

    /**
     * A tuple naming a relation the namespace does not define would be unreachable by any check —
     * silently granting nothing, forever, while looking exactly like a successful grant.
     */
    private void requireDefinedRelation(UUID tenantId, TupleChange change) {
        NamespaceConfig config = namespaceCatalog.require(tenantId, change.namespace());
        if (!config.defines(change.relation())) {
            throw new UnknownRelationException(change.namespace(), change.relation());
        }
    }
}
