package com.sahilkalgutkar.trust.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * A refresh token, stored hashed, and belonging to a rotation <em>family</em>.
 *
 * <p>Each refresh rotates: the presented token is consumed and a new one issued carrying the same
 * {@code familyId}. A stolen token therefore only works until the legitimate client refreshes once
 * — after that, one of the two parties presents a consumed token, and the whole family is revoked.
 * That is the point of the family: the provider cannot tell the thief from the victim, so it stops
 * trusting the lineage rather than guessing.
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    private UUID id;

    @TenantId
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "family_id", nullable = false)
    private UUID familyId;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(nullable = false)
    private String scope;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected RefreshTokenEntity() {
    }

    public RefreshTokenEntity(UUID id, String tokenHash, UUID familyId, String clientId,
                              UUID userId, String scope, Instant expiresAt) {
        this.id = id;
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.clientId = clientId;
        this.userId = userId;
        this.scope = scope;
        this.expiresAt = expiresAt;
    }

    public boolean isUsable(Instant now) {
        return consumedAt == null && revokedAt == null && now.isBefore(expiresAt);
    }

    public void consume(Instant at) {
        this.consumedAt = at;
    }

    public void revoke(Instant at) {
        if (this.revokedAt == null) {
            this.revokedAt = at;
        }
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public UUID getFamilyId() {
        return familyId;
    }

    public String getClientId() {
        return clientId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getScope() {
        return scope;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }
}
