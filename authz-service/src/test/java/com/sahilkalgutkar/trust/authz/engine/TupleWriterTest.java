package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.audit.AuditRecorder;
import com.sahilkalgutkar.trust.authz.domain.RelationTupleEntity;
import com.sahilkalgutkar.trust.authz.model.NamespaceConfig;
import com.sahilkalgutkar.trust.authz.model.Rewrite;
import com.sahilkalgutkar.trust.authz.model.SubjectRef;
import com.sahilkalgutkar.trust.authz.model.UnknownRelationException;
import com.sahilkalgutkar.trust.authz.model.Zookie;
import com.sahilkalgutkar.trust.authz.repo.RelationTupleRepository;
import com.sahilkalgutkar.trust.authz.repo.RevisionSequence;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TupleWriterTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final NamespaceConfig DOCUMENT = new NamespaceConfig("document", Map.of(
            "owner", new Rewrite.This(),
            "viewer", new Rewrite.This()));

    private final RelationTupleRepository repository = mock(RelationTupleRepository.class);
    private final NamespaceCatalog catalog = mock(NamespaceCatalog.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final AtomicLong sequence = new AtomicLong();

    private TupleWriter writer;

    @BeforeEach
    void setUp() {
        RevisionSequence revisions = mock(RevisionSequence.class);
        when(revisions.next()).thenAnswer(invocation -> sequence.incrementAndGet());
        when(catalog.require(any(), anyString())).thenReturn(DOCUMENT);
        when(repository
                .findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
                        anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(Optional.empty());
        writer = new TupleWriter(repository, catalog, revisions, auditRecorder,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void aWriteStoresTheTupleAndReturnsItsRevision() {
        Zookie zookie = writer.apply(TENANT, "user:admin", List.of(write("owner", "user:ada")));

        ArgumentCaptor<RelationTupleEntity> saved = ArgumentCaptor.forClass(RelationTupleEntity.class);
        verify(repository).save(saved.capture());
        assertThat(saved.getValue().getNamespace()).isEqualTo("document");
        assertThat(saved.getValue().getObjectId()).isEqualTo("readme");
        assertThat(saved.getValue().getRelation()).isEqualTo("owner");
        assertThat(saved.getValue().subject()).isEqualTo(SubjectRef.parse("user:ada"));
        assertThat(zookie).isEqualTo(Zookie.of(saved.getValue().getRevision()));
    }

    /** A retry after a timeout must not double-write, and must not fail. */
    @Test
    void writingATupleThatAlreadyExistsIsANoOp() {
        when(repository
                .findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
                        "document", "readme", "owner", "user", "ada", ""))
                .thenReturn(Optional.of(existing()));

        writer.apply(TENANT, "user:admin", List.of(write("owner", "user:ada")));

        verify(repository, never()).save(any());
    }

    @Test
    void aDeleteRemovesTheTuple() {
        RelationTupleEntity tuple = existing();
        when(repository
                .findByNamespaceAndObjectIdAndRelationAndSubjectTypeAndSubjectIdAndSubjectRelation(
                        "document", "readme", "owner", "user", "ada", ""))
                .thenReturn(Optional.of(tuple));

        writer.apply(TENANT, "user:admin", List.of(delete("owner", "user:ada")));

        verify(repository).delete(tuple);
    }

    @Test
    void deletingATupleThatIsNotThereIsAlsoANoOp() {
        writer.apply(TENANT, "user:admin", List.of(delete("owner", "user:ada")));

        verify(repository, never()).delete(any());
    }

    /**
     * The whole batch shares one revision, so the zookie a caller gets back provably covers every
     * change in it — including the removal half of a remove-then-add pair.
     */
    @Test
    void everyChangeInABatchLandsAtOneRevision() {
        Zookie zookie = writer.apply(TENANT, "user:admin", List.of(
                delete("owner", "user:ada"),
                write("viewer", "user:ada"),
                write("viewer", "user:bob")));

        ArgumentCaptor<RelationTupleEntity> saved = ArgumentCaptor.forClass(RelationTupleEntity.class);
        verify(repository, org.mockito.Mockito.times(2)).save(saved.capture());
        assertThat(saved.getAllValues()).extracting(RelationTupleEntity::getRevision)
                .containsOnly(zookie.revision());
        assertThat(sequence.get()).isEqualTo(1);
    }

    @Test
    void aRelationTheNamespaceDoesNotDefineIsRejectedBeforeAnythingIsWritten() {
        assertThatThrownBy(() -> writer.apply(TENANT, "user:admin", List.of(
                write("owner", "user:ada"),
                write("administer", "user:ada"))))
                .isInstanceOf(UnknownRelationException.class);

        verify(repository, never()).save(any());
    }

    @Test
    void anEmptyBatchIsRejected() {
        assertThatThrownBy(() -> writer.apply(TENANT, "user:admin", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> writer.apply(TENANT, "user:admin", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void everyChangeIsAuditedWithWhoDidItAndWhatChanged() {
        writer.apply(TENANT, "user:admin", List.of(write("owner", "user:ada")));

        ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditRecorder).record(event.capture());
        assertThat(event.getValue().action()).isEqualTo("tuple.write");
        assertThat(event.getValue().actor()).isEqualTo("user:admin");
        assertThat(event.getValue().resourceType()).isEqualTo("document");
        assertThat(event.getValue().resourceId()).isEqualTo("readme");
        assertThat(event.getValue().attributes())
                .containsEntry("relation", "owner")
                .containsEntry("subject", "user:ada");
    }

    @Test
    void aDeleteIsAuditedAsADelete() {
        writer.apply(TENANT, "user:admin", List.of(delete("owner", "user:ada")));

        ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditRecorder).record(event.capture());
        assertThat(event.getValue().action()).isEqualTo("tuple.delete");
    }

    @Test
    void aMalformedChangeIsRejectedAtConstruction() {
        assertThatThrownBy(() -> new TupleChange(null, "document", "readme", "owner",
                SubjectRef.parse("user:ada"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TupleChange(TupleChange.Operation.WRITE, " ", "readme", "owner",
                SubjectRef.parse("user:ada"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TupleChange(TupleChange.Operation.WRITE, "document", "", "owner",
                SubjectRef.parse("user:ada"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TupleChange(TupleChange.Operation.WRITE, "document", "readme", null,
                SubjectRef.parse("user:ada"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TupleChange(TupleChange.Operation.WRITE, "document", "readme",
                "owner", null)).isInstanceOf(IllegalArgumentException.class);
    }

    private static TupleChange write(String relation, String subject) {
        return new TupleChange(TupleChange.Operation.WRITE, "document", "readme", relation,
                SubjectRef.parse(subject));
    }

    private static TupleChange delete(String relation, String subject) {
        return new TupleChange(TupleChange.Operation.DELETE, "document", "readme", relation,
                SubjectRef.parse(subject));
    }

    private static RelationTupleEntity existing() {
        return new RelationTupleEntity(UUID.randomUUID(), "document", "readme", "owner",
                SubjectRef.parse("user:ada"), 1);
    }
}
