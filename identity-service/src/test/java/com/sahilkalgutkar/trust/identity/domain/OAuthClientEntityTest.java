package com.sahilkalgutkar.trust.identity.domain;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthClientEntityTest {

    private OAuthClientEntity client;

    @BeforeEach
    void setUp() {
        client = new OAuthClientEntity(UUID.randomUUID(), "web-app", "Web App");
        client.setRedirectUris("https://app.acme.test/callback, https://app.acme.test/other");
        client.setGrantTypes("authorization_code,refresh_token");
        client.setScopes("openid,profile");
    }

    @Test
    void aRegisteredRedirectUriIsAccepted() {
        assertThat(client.allowsRedirectUri("https://app.acme.test/callback")).isTrue();
        assertThat(client.allowsRedirectUri("https://app.acme.test/other")).isTrue();
    }

    /**
     * Exact match only. Every one of these is a real open-redirect shape that prefix or
     * "startsWith" matching would wave through.
     */
    @Test
    void nearMissesAreRejected() {
        assertThat(client.allowsRedirectUri("https://app.acme.test/callback/../evil")).isFalse();
        assertThat(client.allowsRedirectUri("https://app.acme.test/callback.evil.test")).isFalse();
        assertThat(client.allowsRedirectUri("https://app.acme.test/callback?next=evil")).isFalse();
        assertThat(client.allowsRedirectUri("https://app.acme.test.evil.test/callback")).isFalse();
        assertThat(client.allowsRedirectUri("http://app.acme.test/callback")).isFalse();
        assertThat(client.allowsRedirectUri(null)).isFalse();
    }

    @Test
    void aClientWithNoRegisteredUrisAcceptsNone() {
        client.setRedirectUris("");

        assertThat(client.allowsRedirectUri("https://app.acme.test/callback")).isFalse();
        assertThat(client.redirectUriSet()).isEmpty();
    }

    @Test
    void grantTypesAndScopesAreParsedFromTheCsvColumn() {
        assertThat(client.allowsGrantType("authorization_code")).isTrue();
        assertThat(client.allowsGrantType("client_credentials")).isFalse();
        assertThat(client.grantTypeSet()).containsExactly("authorization_code", "refresh_token");
        assertThat(client.allowedScopes()).containsExactly("openid", "profile");
    }

    @Test
    void surroundingWhitespaceInTheCsvIsIgnored() {
        client.setScopes(" openid , profile ,, ");

        assertThat(client.allowedScopes()).containsExactly("openid", "profile");
    }

    @Test
    void aClientWithNoSecretIsAPublicClient() {
        assertThat(client.isPublicClient()).isTrue();

        client.setClientSecretHash("$2a$10$hash");
        assertThat(client.isPublicClient()).isFalse();

        client.setClientSecretHash("   ");
        assertThat(client.isPublicClient()).isTrue();
    }

    @Test
    void pkceIsRequiredUnlessExplicitlyTurnedOff() {
        assertThat(client.isRequirePkce()).isTrue();

        client.setRequirePkce(false);
        assertThat(client.isRequirePkce()).isFalse();
    }
}
