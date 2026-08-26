package com.sahilkalgutkar.trust.audit.chain;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import com.sahilkalgutkar.trust.common.hash.HashChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every test below is a way of interfering with the record, run against the detector.
 *
 * <p>They all assume an attacker who already has write access to the audit table — which is the only
 * interesting case. Tampering that requires no privileges is not tampering, it is a bug.
 */
class AuditChainVerifierTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

    private AuditStore store;
    private AuditChainService chainService;
    private AuditChainVerifier verifier;

    @BeforeEach
    void setUp() {
        store = new AuditStore();
        AuditEventRepository repository = store.repository();
        chainService = new AuditChainService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
        verifier = new AuditChainVerifier(repository);
    }

    @Test
    void anEmptyChainIsIntact() {
        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isTrue();
        assertThat(result.recordsChecked()).isZero();
        assertThat(result.headHash()).isEqualTo(HashChain.GENESIS);
    }

    @Test
    void anUntouchedChainIsIntact() {
        appendEvents(25);

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(25);
        assertThat(result.brokenAtSeq()).isNull();
        assertThat(result.headHash()).isEqualTo(store.at(TENANT, 25).orElseThrow().getHash());
    }

    @Test
    void aChainLongerThanOnePageIsWalkedInFull() {
        appendEvents(1_200);

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(1_200);
    }

    /** Editing what an event says: the payload no longer produces the stored hash. */
    @Test
    void rewritingARecordsPayloadIsDetected() {
        appendEvents(5);
        AuditEventEntity original = store.at(TENANT, 3).orElseThrow();
        AuditEvent forged = AuditEvent.builder(TENANT.toString(), "token.issued")
                .eventId(original.getEventId())
                .actor("user:someone-else")
                .occurredAt(NOW)
                .build();
        store.tamper(TENANT, 3, copyWithPayload(original, CanonicalJson.string(forged)));

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(3);
        assertThat(result.reason()).contains("does not match the record's contents");
    }

    /**
     * The thorough version of the attack: rewrite the payload <em>and</em> recompute this record's
     * own hash. It still fails, because the next record's prev_hash was computed from the old one.
     */
    @Test
    void rewritingARecordAndRecomputingItsOwnHashIsStillDetectedAtTheNextRecord() {
        appendEvents(5);
        AuditEventEntity original = store.at(TENANT, 3).orElseThrow();
        AuditEvent forged = AuditEvent.builder(TENANT.toString(), "token.issued")
                .eventId(original.getEventId())
                .actor("user:someone-else")
                .occurredAt(NOW)
                .build();
        String forgedPayload = CanonicalJson.string(forged);
        String recomputed = HashChain.link(original.getPrevHash(),
                forgedPayload.getBytes(StandardCharsets.UTF_8));
        store.tamper(TENANT, 3, copy(original, forgedPayload, original.getPrevHash(), recomputed,
                "user:someone-else"));

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(4);
        assertThat(result.reason()).contains("does not chain to its predecessor");
    }

    /** Removing a record outright: the hashes of the survivors still agree, but a position is gone. */
    @Test
    void deletingARecordIsDetectedAsAGapRatherThanGoingUnnoticed() {
        appendEvents(5);
        store.delete(TENANT, 3);

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(3);
        assertThat(result.reason()).contains("Missing record at position 3");
    }

    @Test
    void deletingTheOldestRecordIsDetected() {
        appendEvents(3);
        store.delete(TENANT, 1);

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(1);
    }

    /**
     * The subtle one. Audit logs are read through queries over the indexed columns, so changing only
     * {@code actor} would leave the chain verifying while every report named the wrong person.
     */
    @Test
    void rewritingAnIndexedColumnWithoutTouchingThePayloadIsDetected() {
        appendEvents(4);
        AuditEventEntity original = store.at(TENANT, 2).orElseThrow();
        store.tamper(TENANT, 2, copy(original, original.getPayload(), original.getPrevHash(),
                original.getHash(), "user:innocent-bystander"));

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(2);
        assertThat(result.reason()).contains("Indexed columns disagree");
    }

    @Test
    void repointingARecordsPrevHashIsDetected() {
        appendEvents(4);
        AuditEventEntity original = store.at(TENANT, 3).orElseThrow();
        store.tamper(TENANT, 3, copy(original, original.getPayload(), HashChain.GENESIS,
                original.getHash(), original.getActor()));

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(3);
        assertThat(result.reason()).contains("does not chain to its predecessor");
    }

    @Test
    void anUnparseablePayloadIsTreatedAsTampering() {
        appendEvents(2);
        AuditEventEntity original = store.at(TENANT, 1).orElseThrow();
        String garbage = "{not json";
        store.tamper(TENANT, 1, copy(original, garbage, original.getPrevHash(),
                HashChain.link(original.getPrevHash(), garbage.getBytes(StandardCharsets.UTF_8)),
                original.getActor()));

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(1);
    }

    @Test
    void theFirstBreakIsReportedRatherThanTheLast() {
        appendEvents(6);
        store.delete(TENANT, 2);
        store.delete(TENANT, 5);

        ChainVerification result = verifier.verify(TENANT);

        assertThat(result.brokenAtSeq()).isEqualTo(2);
        assertThat(result.recordsChecked()).isEqualTo(1);
    }

    @Test
    void oneTenantsTamperingDoesNotImplicateAnother() {
        appendEvents(3);
        UUID otherTenant = UUID.fromString("22222222-2222-2222-2222-222222222222");
        chainService.append(AuditEvent.builder(otherTenant.toString(), "token.issued")
                .eventId("other-1").actor("user:bob").occurredAt(NOW).build());
        store.delete(TENANT, 2);

        assertThat(verifier.verify(TENANT).intact()).isFalse();
        assertThat(verifier.verify(otherTenant).intact()).isTrue();
    }

    // ------------------------------------------------------------------ helpers

    private void appendEvents(int count) {
        for (int i = 1; i <= count; i++) {
            chainService.append(AuditEvent.builder(TENANT.toString(), "token.issued")
                    .eventId("evt-" + i)
                    .actor("user:ada")
                    .occurredAt(NOW)
                    .build());
        }
    }

    private static AuditEventEntity copyWithPayload(AuditEventEntity original, String payload) {
        return copy(original, payload, original.getPrevHash(), original.getHash(), original.getActor());
    }

    private static AuditEventEntity copy(AuditEventEntity original, String payload, String prevHash,
                                         String hash, String actor) {
        return new AuditEventEntity(original.getId(), original.getTenantId(), original.getSeq(),
                original.getEventId(), actor, original.getAction(), original.getResourceType(),
                original.getResourceId(), original.getOutcome() == null
                ? AuditOutcome.SUCCESS : original.getOutcome(),
                original.getOccurredAt(), payload, prevHash, hash, original.getRecordedAt());
    }
}
