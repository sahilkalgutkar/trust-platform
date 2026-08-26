package com.sahilkalgutkar.trust.audit.domain;

import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/**
 * One link in a tenant's audit chain.
 *
 * <p>Every field is write-once: there is no setter, no update path, and nothing in this service
 * issues an UPDATE against this table. An audit record that can be corrected is an audit record
 * that can be edited.
 */
@Entity
@Table(name = "audit_events")
public class AuditEventEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private long seq;

    @Column(name = "event_id", nullable = false)
    private String eventId;

    @Column(nullable = false)
    private String actor;

    @Column(nullable = false)
    private String action;

    @Column(name = "resource_type")
    private String resourceType;

    @Column(name = "resource_id")
    private String resourceId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditOutcome outcome;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(nullable = false, length = 8192)
    private String payload;

    @Column(name = "prev_hash", nullable = false)
    private String prevHash;

    @Column(nullable = false)
    private String hash;

    @Column(name = "recorded_at", nullable = false)
    private Instant recordedAt = Instant.now();

    protected AuditEventEntity() {
    }

    public AuditEventEntity(UUID id, UUID tenantId, long seq, String eventId, String actor,
                            String action, String resourceType, String resourceId,
                            AuditOutcome outcome, Instant occurredAt, String payload,
                            String prevHash, String hash, Instant recordedAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.seq = seq;
        this.eventId = eventId;
        this.actor = actor;
        this.action = action;
        this.resourceType = resourceType;
        this.resourceId = resourceId;
        this.outcome = outcome;
        this.occurredAt = occurredAt;
        this.payload = payload;
        this.prevHash = prevHash;
        this.hash = hash;
        this.recordedAt = recordedAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public long getSeq() {
        return seq;
    }

    public String getEventId() {
        return eventId;
    }

    public String getActor() {
        return actor;
    }

    public String getAction() {
        return action;
    }

    public String getResourceType() {
        return resourceType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public AuditOutcome getOutcome() {
        return outcome;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getPayload() {
        return payload;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public String getHash() {
        return hash;
    }

    public Instant getRecordedAt() {
        return recordedAt;
    }
}
