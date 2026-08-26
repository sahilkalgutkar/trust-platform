package com.sahilkalgutkar.trust.authz.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** An audit event waiting to reach Kafka. Not tenant-discriminated — the drain runs unbound. */
@Entity
@Table(name = "audit_outbox")
public class AuditOutboxEntity {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false, length = 8192)
    private String payload;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "published_at")
    private Instant publishedAt;

    protected AuditOutboxEntity() {
    }

    public AuditOutboxEntity(UUID id, UUID tenantId, String payload) {
        this.id = id;
        this.tenantId = tenantId;
        this.payload = payload;
    }

    public void markPublished(Instant at) {
        this.publishedAt = at;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getPayload() {
        return payload;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }
}
