package com.sahilkalgutkar.trust.authz.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthzPropertiesTest {

    @Test
    void theIssuerAndJwksUriAreDerivedFromTheTenant() {
        AuthzProperties properties = new AuthzProperties();
        properties.setIssuerBaseUrl("https://id.acme.test");

        assertThat(properties.issuerFor("acme")).isEqualTo("https://id.acme.test/t/acme");
        assertThat(properties.jwksUriFor("acme")).isEqualTo("https://id.acme.test/t/acme/oauth2/jwks");
    }

    @Test
    void aTrailingSlashDoesNotProduceADoubleSlash() {
        AuthzProperties properties = new AuthzProperties();
        properties.setIssuerBaseUrl("https://id.acme.test/");

        assertThat(properties.issuerFor("acme")).isEqualTo("https://id.acme.test/t/acme");
    }

    /**
     * The case that breaks the moment anything is deployed behind a service mesh or a compose
     * network: tokens are issued with a public issuer, but the keys are fetched over an internal
     * address. The issuer comparison must keep using the public value.
     */
    @Test
    void theJwksUrlCanPointSomewhereOtherThanTheIssuer() {
        AuthzProperties properties = new AuthzProperties();
        properties.setIssuerBaseUrl("https://id.acme.test");
        properties.setJwksBaseUrl("http://identity-service:8081");

        assertThat(properties.issuerFor("acme")).isEqualTo("https://id.acme.test/t/acme");
        assertThat(properties.jwksUriFor("acme"))
                .isEqualTo("http://identity-service:8081/t/acme/oauth2/jwks");
    }

    @Test
    void anUnsetJwksUrlFallsBackToTheIssuer() {
        AuthzProperties properties = new AuthzProperties();
        properties.setIssuerBaseUrl("https://id.acme.test");

        assertThat(properties.jwksUriFor("acme"))
                .isEqualTo("https://id.acme.test/t/acme/oauth2/jwks");
    }

    /**
     * This service caches JWKS; the identity service keeps retired keys published for far longer.
     * If that ordering ever inverted, rotation would start rejecting live traffic here.
     */
    @Test
    void theJwksCacheIsShortRelativeToTheIdentityServicesRetiredKeyWindow() {
        AuthzProperties properties = new AuthzProperties();

        assertThat(properties.getJwksCacheTtl()).isLessThan(java.time.Duration.ofHours(24));
    }
}
