package com.sahilkalgutkar.trust.identity.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class IdentityPropertiesTest {

    @Test
    void theIssuerIsTheTenantsOwnPath() {
        IdentityProperties properties = new IdentityProperties();
        properties.setIssuerBaseUrl("https://id.acme.test");

        assertThat(properties.issuerFor("acme")).isEqualTo("https://id.acme.test/t/acme");
    }

    @Test
    void aTrailingSlashOnTheBaseUrlDoesNotProduceADoubleSlash() {
        IdentityProperties properties = new IdentityProperties();
        properties.setIssuerBaseUrl("https://id.acme.test/");

        assertThat(properties.issuerFor("acme")).isEqualTo("https://id.acme.test/t/acme");
    }

    @Test
    void theDefaultsAreTheConservativeEndOfTheSecurityBcp() {
        IdentityProperties properties = new IdentityProperties();

        assertThat(properties.getAccessTokenTtl()).isEqualTo(Duration.ofMinutes(15));
        assertThat(properties.getAuthorizationCodeTtl()).isEqualTo(Duration.ofMinutes(1));
        assertThat(properties.getRefreshTokenTtl()).isEqualTo(Duration.ofDays(30));
    }

    /** A retired key must outlive the tokens it signed, or rotation breaks live sessions. */
    @Test
    void theRetiredKeyGracePeriodExceedsTheAccessTokenLifetime() {
        IdentityProperties properties = new IdentityProperties();

        assertThat(properties.getRetiredKeyGracePeriod())
                .isGreaterThan(properties.getAccessTokenTtl());
    }
}
