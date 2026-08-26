package com.sahilkalgutkar.trust.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * One RSA signing keypair belonging to one tenant.
 *
 * <p>Keys are per-tenant rather than platform-wide on purpose: combined with a per-tenant issuer,
 * it means a token minted for tenant A does not merely fail an {@code iss} check at tenant B — it
 * fails signature verification against B's JWKS, so a relying party that forgets the issuer check
 * still rejects it.
 */
@Entity
@Table(name = "signing_keys")
public class SigningKeyEntity {

    public static final String ACTIVE = "ACTIVE";
    public static final String RETIRED = "RETIRED";

    @Id
    private String kid;

    @TenantId
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(nullable = false)
    private String algorithm = "RS256";

    @Column(name = "public_jwk", nullable = false, length = 4096)
    private String publicJwk;

    @Column(name = "private_key_wrapped", nullable = false, length = 8192)
    private String privateKeyWrapped;

    @Column(nullable = false)
    private String status = ACTIVE;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "retired_at")
    private Instant retiredAt;

    protected SigningKeyEntity() {
    }

    public SigningKeyEntity(String kid, String publicJwk, String privateKeyWrapped) {
        this.kid = kid;
        this.publicJwk = publicJwk;
        this.privateKeyWrapped = privateKeyWrapped;
    }

    public void retire(Instant at) {
        this.status = RETIRED;
        this.retiredAt = at;
    }

    public boolean isActive() {
        return ACTIVE.equals(status);
    }

    public String getKid() {
        return kid;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getPublicJwk() {
        return publicJwk;
    }

    public String getPrivateKeyWrapped() {
        return privateKeyWrapped;
    }

    public String getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRetiredAt() {
        return retiredAt;
    }
}
