package com.sahilkalgutkar.trust.identity.config;

import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import org.hibernate.cfg.AvailableSettings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class TenantIdentifierResolverTest {

    private final TenantIdentifierResolver resolver = new TenantIdentifierResolver();

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    void theBoundTenantIsWhatHibernateSees() {
        UUID tenant = UUID.randomUUID();
        TenantContext.set(tenant.toString());

        assertThat(resolver.resolveCurrentTenantIdentifier()).isEqualTo(tenant);
    }

    /**
     * The fail-closed default. Sessions open on paths with no tenant bound — Flyway, the outbox
     * drain, the filter's own slug lookup — and the nil tenant keeps the predicate in the SQL while
     * matching nothing, rather than falling back to some tenant's real data.
     */
    @Test
    void anUnboundContextResolvesToTheNilTenantRatherThanNull() {
        assertThat(resolver.resolveCurrentTenantIdentifier())
                .isEqualTo(TenantIdentifierResolver.NIL_TENANT)
                .isEqualTo(new UUID(0L, 0L));
    }

    @Test
    void aTenantThatIsNotAUuidAlsoResolvesToNil() {
        TenantContext.set("not-a-uuid");

        assertThat(resolver.resolveCurrentTenantIdentifier())
                .isEqualTo(TenantIdentifierResolver.NIL_TENANT);
    }

    @Test
    void theResolverRegistersItselfWithHibernate() {
        Map<String, Object> properties = new HashMap<>();

        resolver.customize(properties);

        assertThat(properties).containsEntry(AvailableSettings.MULTI_TENANT_IDENTIFIER_RESOLVER, resolver);
    }

    @Test
    void existingSessionsAreNotRevalidatedAgainstTheCurrentTenant() {
        assertThat(resolver.validateExistingCurrentSessions()).isFalse();
    }
}
