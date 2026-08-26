package com.sahilkalgutkar.trust.common.hash;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CanonicalJsonTest {

    @Test
    void mapKeysAreSortedRegardlessOfInsertionOrder() {
        Map<String, String> oneOrder = new LinkedHashMap<>();
        oneOrder.put("zebra", "1");
        oneOrder.put("alpha", "2");

        Map<String, String> otherOrder = new LinkedHashMap<>();
        otherOrder.put("alpha", "2");
        otherOrder.put("zebra", "1");

        assertThat(CanonicalJson.string(oneOrder))
                .isEqualTo(CanonicalJson.string(otherOrder))
                .isEqualTo("{\"alpha\":\"2\",\"zebra\":\"1\"}");
    }

    @Test
    void instantsSerializeAsIso8601NotFloatingPointEpochSeconds() {
        String json = CanonicalJson.string(Map.of("at", Instant.parse("2026-08-25T12:00:00Z")));

        assertThat(json).isEqualTo("{\"at\":\"2026-08-25T12:00:00Z\"}");
    }

    @Test
    void outputIsCompactSoWhitespaceCannotChangeAHash() {
        assertThat(CanonicalJson.string(Map.of("a", "b"))).doesNotContain("\n", "  ");
    }

    @Test
    void recordPropertiesSerializeInAlphabeticalOrder() {
        AuditEvent event = AuditEvent.builder("acme", "token.issued")
                .eventId("evt-1")
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .build();

        String json = CanonicalJson.string(event);

        assertThat(json.indexOf("\"action\"")).isLessThan(json.indexOf("\"tenantId\""));
    }

    @Test
    void bytesAreTheUtf8EncodingOfTheString() {
        Map<String, String> value = Map.of("name", "Ärger");

        assertThat(CanonicalJson.bytes(value))
                .isEqualTo(CanonicalJson.string(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    @Test
    void parseRoundTripsAnEvent() {
        AuditEvent original = AuditEvent.builder("acme", "tuple.written")
                .actor("user:1")
                .resource("document", "readme")
                .attribute("relation", "viewer")
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .build();

        AuditEvent parsed = CanonicalJson.parse(CanonicalJson.string(original), AuditEvent.class);

        assertThat(parsed).isEqualTo(original);
    }

    @Test
    void unserializableValuesFailLoudly() {
        assertThatThrownBy(() -> CanonicalJson.string(new Object()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not canonically serializable");
    }

    @Test
    void malformedJsonFailsLoudly() {
        assertThatThrownBy(() -> CanonicalJson.parse("{not json", AuditEvent.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AuditEvent");
    }
}
