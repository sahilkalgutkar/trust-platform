package com.sahilkalgutkar.trust.common.audit;

import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuditEventTest {

    @Test
    void builderFillsInSensibleDefaults() {
        AuditEvent event = AuditEvent.builder("acme", "token.issued").build();

        assertThat(event.eventId()).isNotBlank();
        assertThat(event.actor()).isEqualTo("system");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.attributes()).isEmpty();
        assertThat(event.occurredAt()).isNotNull();
    }

    @Test
    void builderCarriesEveryFieldThrough() {
        AuditEvent event = AuditEvent.builder("acme", "check.evaluated")
                .eventId("evt-1")
                .actor("user:42")
                .resource("document", "readme")
                .outcome(AuditOutcome.DENIED)
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .attribute("relation", "viewer")
                .build();

        assertThat(event.eventId()).isEqualTo("evt-1");
        assertThat(event.actor()).isEqualTo("user:42");
        assertThat(event.resourceType()).isEqualTo("document");
        assertThat(event.resourceId()).isEqualTo("readme");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(event.occurredAt()).isEqualTo(Instant.parse("2026-08-25T12:00:00Z"));
        assertThat(event.attributes()).containsExactly(Map.entry("relation", "viewer"));
    }

    @Test
    void nullAttributeValuesAreDroppedRatherThanStoredAsNull() {
        AuditEvent event = AuditEvent.builder("acme", "token.issued")
                .attribute("scope", null)
                .attribute("client", "web")
                .build();

        assertThat(event.attributes()).containsOnlyKeys("client");
    }

    @Test
    void identicalEventsHashIdenticallyRegardlessOfAttributeInsertionOrder() {
        Map<String, String> oneOrder = new LinkedHashMap<>();
        oneOrder.put("zebra", "1");
        oneOrder.put("alpha", "2");
        Map<String, String> otherOrder = new LinkedHashMap<>();
        otherOrder.put("alpha", "2");
        otherOrder.put("zebra", "1");

        Instant at = Instant.parse("2026-08-25T12:00:00Z");
        AuditEvent one = new AuditEvent("evt-1", "acme", "user:1", "a", null, null, AuditOutcome.SUCCESS, at, oneOrder);
        AuditEvent other = new AuditEvent("evt-1", "acme", "user:1", "a", null, null, AuditOutcome.SUCCESS, at, otherOrder);

        assertThat(CanonicalJson.string(one)).isEqualTo(CanonicalJson.string(other));
    }

    @Test
    void attributesAreDefensivelyCopiedSoTheCallerCannotMutateAHashedEvent() {
        Map<String, String> mutable = new LinkedHashMap<>();
        mutable.put("scope", "openid");
        AuditEvent event = AuditEvent.builder("acme", "token.issued")
                .attribute("scope", "openid")
                .build();
        mutable.put("scope", "admin");

        assertThat(event.attributes()).containsExactly(Map.entry("scope", "openid"));
        assertThatThrownBy(() -> event.attributes().put("scope", "admin"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void missingRequiredFieldsAreRejectedAtConstruction() {
        Instant at = Instant.now();

        assertThatThrownBy(() -> new AuditEvent("", "acme", "u", "a", null, null, null, at, null))
                .hasMessageContaining("eventId");
        assertThatThrownBy(() -> new AuditEvent("evt", " ", "u", "a", null, null, null, at, null))
                .hasMessageContaining("tenantId");
        assertThatThrownBy(() -> new AuditEvent("evt", "acme", "u", null, null, null, null, at, null))
                .hasMessageContaining("action");
    }

    @Test
    void nullOptionalsFallBackRatherThanNullingOutTheHashInput() {
        AuditEvent event = new AuditEvent("evt", "acme", null, "a", null, null, null, null, null);

        assertThat(event.actor()).isEqualTo("system");
        assertThat(event.outcome()).isEqualTo(AuditOutcome.SUCCESS);
        assertThat(event.occurredAt()).isEqualTo(Instant.EPOCH);
        assertThat(event.attributes()).isEmpty();
    }

    /**
     * The end-to-end bug this guards against: an event hashed with nanosecond precision, stored in
     * a TIMESTAMPTZ column that holds microseconds, and then read back as a different value — which
     * makes an untampered audit chain fail verification.
     */
    @Test
    void occurredAtIsTruncatedToWhatTheDatabaseCanActuallyStore() {
        Instant nanos = Instant.parse("2026-08-25T12:00:00.123456789Z");

        AuditEvent event = AuditEvent.builder("acme", "token.issued").occurredAt(nanos).build();

        assertThat(event.occurredAt()).isEqualTo(Instant.parse("2026-08-25T12:00:00.123456Z"));
        assertThat(event.occurredAt().getNano() % 1_000).isZero();
    }

    @Test
    void aTruncatedTimestampSurvivesASerializationRoundTrip() {
        AuditEvent original = AuditEvent.builder("acme", "token.issued")
                .occurredAt(Instant.parse("2026-08-25T12:00:00.123456789Z"))
                .build();

        AuditEvent parsed = CanonicalJson.parse(CanonicalJson.string(original), AuditEvent.class);

        assertThat(parsed.occurredAt()).isEqualTo(original.occurredAt());
        assertThat(CanonicalJson.string(parsed)).isEqualTo(CanonicalJson.string(original));
    }

    @Test
    void auditTopicIsVersionedSoConsumersCanBeMigrated() {
        assertThat(AuditTopics.AUDIT_EVENTS).isEqualTo("trust.audit.v1");
    }
}
