package com.sahilkalgutkar.trust.authz.config;

import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.context.spi.CurrentTenantIdentifierResolver;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * Feeds the token-proven tenant into Hibernate's discriminator-based multi-tenancy, so every tuple
 * query carries a tenant predicate that no service code had to remember to add.
 *
 * <p>The nil-tenant fallback is the fail-closed default: sessions open on paths with no tenant
 * bound (Flyway, the outbox drain), and matching nothing is the right behaviour there.
 */
@Component
public class TenantIdentifierResolver
        implements CurrentTenantIdentifierResolver<UUID>, HibernatePropertiesCustomizer {

    public static final UUID NIL_TENANT = new UUID(0L, 0L);

    @Override
    public UUID resolveCurrentTenantIdentifier() {
        return TenantContext.current().map(TenantIdentifierResolver::parseOrNil).orElse(NIL_TENANT);
    }

    @Override
    public boolean validateExistingCurrentSessions() {
        return false;
    }

    @Override
    public void customize(Map<String, Object> hibernateProperties) {
        hibernateProperties.put(AvailableSettings.MULTI_TENANT_IDENTIFIER_RESOLVER, this);
    }

    private static UUID parseOrNil(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return NIL_TENANT;
        }
    }
}
