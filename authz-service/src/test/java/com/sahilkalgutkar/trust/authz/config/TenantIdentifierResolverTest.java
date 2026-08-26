package com.sahilkalgutkar.trust.authz.config;

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
    void clear() {
        TenantContext.clear();
    }

    @Test
    void theTokenProvenTenantIsWhatHibernateSees() {
        UUID tenant = UUID.randomUUID();
        TenantContext.set(tenant.toString());

        assertThat(resolver.resolveCurrentTenantIdentifier()).isEqualTo(tenant);
    }

    @Test
    void anUnboundContextMatchesNothingRatherThanEverything() {
        assertThat(resolver.resolveCurrentTenantIdentifier())
                .isEqualTo(TenantIdentifierResolver.NIL_TENANT);
    }

    @Test
    void aTenantThatIsNotAUuidAlsoMatchesNothing() {
        TenantContext.set("../../admin");

        assertThat(resolver.resolveCurrentTenantIdentifier())
                .isEqualTo(TenantIdentifierResolver.NIL_TENANT);
    }

    @Test
    void theResolverRegistersItselfWithHibernate() {
        Map<String, Object> properties = new HashMap<>();

        resolver.customize(properties);

        assertThat(properties).containsEntry(AvailableSettings.MULTI_TENANT_IDENTIFIER_RESOLVER, resolver);
        assertThat(resolver.validateExistingCurrentSessions()).isFalse();
    }
}
