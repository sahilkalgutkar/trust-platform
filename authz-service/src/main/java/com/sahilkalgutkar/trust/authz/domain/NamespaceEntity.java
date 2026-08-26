package com.sahilkalgutkar.trust.authz.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A stored namespace configuration.
 *
 * <p>The tenant is part of the primary key rather than a {@code @TenantId} discriminator here,
 * because the configuration is loaded by the engine on paths where an explicit tenant is already in
 * hand and a composite key expresses the "one config per name per tenant" rule directly.
 */
@Entity
@Table(name = "namespaces")
@IdClass(NamespaceEntity.Key.class)
public class NamespaceEntity {

    @Id
    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Id
    @Column(nullable = false)
    private String name;

    @Column(nullable = false, length = 16384)
    private String config;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    protected NamespaceEntity() {
    }

    public NamespaceEntity(UUID tenantId, String name, String config) {
        this.tenantId = tenantId;
        this.name = name;
        this.config = config;
    }

    public void update(String config, Instant at) {
        this.config = config;
        this.updatedAt = at;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getName() {
        return name;
    }

    public String getConfig() {
        return config;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public static class Key implements Serializable {
        private UUID tenantId;
        private String name;

        public Key() {
        }

        public Key(UUID tenantId, String name) {
            this.tenantId = tenantId;
            this.name = name;
        }

        @Override
        public boolean equals(Object other) {
            if (this == other) {
                return true;
            }
            if (!(other instanceof Key key)) {
                return false;
            }
            return Objects.equals(tenantId, key.tenantId) && Objects.equals(name, key.name);
        }

        @Override
        public int hashCode() {
            return Objects.hash(tenantId, name);
        }
    }
}
