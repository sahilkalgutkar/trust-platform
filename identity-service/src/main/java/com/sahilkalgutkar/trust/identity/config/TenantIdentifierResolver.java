package com.sahilkalgutkar.trust.identity.config;

import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.context.spi.CurrentTenantIdentifierResolver;
import org.springframework.boot.autoconfigure.orm.jpa.HibernatePropertiesCustomizer;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.UUID;

/**
 * Feeds {@link TenantContext} into Hibernate's discriminator-based multi-tenancy.
 *
 * <p>Registering this makes every entity annotated {@code @TenantId} tenant-scoped in the generated
 * SQL rather than in service code — the difference between "we filter by tenant everywhere" and
 * "a query that does not filter by tenant cannot be expressed".
 *
 * <p>The {@link #NIL_TENANT} fallback is the important detail. Hibernate resolves a tenant whenever
 * a session opens, including on paths that legitimately have none bound: the request filter looking
 * up which tenant a slug refers to, Flyway, the outbox drain. Throwing there would break startup;
 * returning some "default" tenant would silently widen those queries. Returning the nil UUID instead
 * fails closed — the SQL still carries a tenant predicate, it just matches nothing.
 */
@Component
public class TenantIdentifierResolver
        implements CurrentTenantIdentifierResolver<UUID>, HibernatePropertiesCustomizer {

    public static final UUID NIL_TENANT = new UUID(0L, 0L);

    @Override
    public UUID resolveCurrentTenantIdentifier() {
        return TenantContext.current()
                .map(TenantIdentifierResolver::parseOrNil)
                .orElse(NIL_TENANT);
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
