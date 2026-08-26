package com.sahilkalgutkar.trust.common.audit;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

/**
 * One security-relevant thing that happened, as published to Kafka and chained into the audit log.
 *
 * <p>This is the payload the hash chain covers, so it is immutable and canonically serializable:
 * {@code attributes} is copied into a {@link TreeMap} on construction, because a hash over a map
 * whose iteration order can change is a hash that fails verification at random.
 *
 * @param eventId    idempotency key — the audit consumer dedupes on it, so a Kafka redelivery does
 *                   not append the same event to the chain twice
 * @param actor      who did it, as {@code type:id} ({@code user:...}, {@code client:...}, {@code system})
 * @param action     dotted verb, e.g. {@code token.issued}, {@code refresh.reuse_detected}
 * @param attributes free-form detail; keep it free of credentials, since audit logs are widely read
 */
public record AuditEvent(
        String eventId,
        String tenantId,
        String actor,
        String action,
        String resourceType,
        String resourceId,
        AuditOutcome outcome,
        Instant occurredAt,
        Map<String, String> attributes) {

    @JsonCreator
    public AuditEvent(
            @JsonProperty("eventId") String eventId,
            @JsonProperty("tenantId") String tenantId,
            @JsonProperty("actor") String actor,
            @JsonProperty("action") String action,
            @JsonProperty("resourceType") String resourceType,
            @JsonProperty("resourceId") String resourceId,
            @JsonProperty("outcome") AuditOutcome outcome,
            @JsonProperty("occurredAt") Instant occurredAt,
            @JsonProperty("attributes") Map<String, String> attributes) {
        if (eventId == null || eventId.isBlank()) {
            throw new IllegalArgumentException("eventId is required");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId is required");
        }
        if (action == null || action.isBlank()) {
            throw new IllegalArgumentException("action is required");
        }
        this.eventId = eventId;
        this.tenantId = tenantId;
        this.actor = actor == null ? "system" : actor;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.outcome = outcome == null ? AuditOutcome.SUCCESS : outcome;
        // Truncated to microseconds, deliberately and at the only place every event passes
        // through. Instant carries nanoseconds; PostgreSQL's TIMESTAMPTZ stores microseconds. An
        // untruncated value therefore survives being hashed but not being stored, so the payload
        // and the column it was written to disagree the moment the row is read back — and the
        // audit verifier correctly reports a chain that nobody tampered with as tampered. Losing
        // precision that no storage in this system can represent costs nothing; discovering the
        // mismatch in production would cost an incident.
        this.occurredAt = (occurredAt == null ? Instant.EPOCH : occurredAt)
                .truncatedTo(ChronoUnit.MICROS);
        this.attributes = attributes == null ? Map.of() : Map.copyOf(new TreeMap<>(attributes));
    }

    public static Builder builder(String tenantId, String action) {
        return new Builder(tenantId, action);
    }

    public static final class Builder {
        private final String tenantId;
        private final String action;
        private String eventId = UUID.randomUUID().toString();
        private String actor = "system";
        private String resourceType;
        private String resourceId;
        private AuditOutcome outcome = AuditOutcome.SUCCESS;
        private Instant occurredAt = Instant.now();
        private final Map<String, String> attributes = new TreeMap<>();

        private Builder(String tenantId, String action) {
            this.tenantId = tenantId;
            this.action = action;
        }

        public Builder eventId(String value) {
            this.eventId = value;
            return this;
        }

        public Builder actor(String value) {
            this.actor = value;
            return this;
        }

        public Builder resource(String type, String id) {
            this.resourceType = type;
            this.resourceId = id;
            return this;
        }

        public Builder outcome(AuditOutcome value) {
            this.outcome = value;
            return this;
        }

        public Builder occurredAt(Instant value) {
            this.occurredAt = value;
            return this;
        }

        public Builder attribute(String key, String value) {
            if (value != null) {
                this.attributes.put(key, value);
            }
            return this;
        }

        public AuditEvent build() {
            return new AuditEvent(eventId, tenantId, actor, action, resourceType, resourceId,
                    outcome, occurredAt, attributes);
        }
    }
}
