package com.sahilkalgutkar.trust.identity.oauth;

import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ScopesTest {

    @Test
    void parseSplitsOnRunsOfWhitespaceAndIgnoresBlanks() {
        assertThat(Scopes.parse("openid  profile\temail")).containsExactly("openid", "profile", "email");
        assertThat(Scopes.parse("  ")).isEmpty();
        assertThat(Scopes.parse(null)).isEmpty();
    }

    @Test
    void anOmittedScopeMeansEverythingTheClientIsRegisteredFor() {
        assertThat(Scopes.resolveRequested(null, Set.of("openid"))).isEqualTo("openid");
    }

    @Test
    void aSubsetOfTheRegisteredScopesIsGrantedAsAsked() {
        assertThat(Scopes.resolveRequested("openid", Set.of("openid", "profile"))).isEqualTo("openid");
    }

    @Test
    void askingForAnUnregisteredScopeIsAnErrorRatherThanASilentTrim() {
        assertThatThrownBy(() -> Scopes.resolveRequested("openid admin", Set.of("openid")))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("exceeds what this client is registered for");
    }

    @Test
    void aRefreshWithoutAnExplicitScopeKeepsWhatWasGranted() {
        assertThat(Scopes.resolveRefreshed(null, "openid profile")).isEqualTo("openid profile");
    }

    @Test
    void aRefreshMayNarrowTheGrantedScope() {
        assertThat(Scopes.resolveRefreshed("openid", "openid profile")).isEqualTo("openid");
    }

    @Test
    void aRefreshMayNotWidenTheGrantedScope() {
        assertThatThrownBy(() -> Scopes.resolveRefreshed("openid admin", "openid"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("never widen");
    }

    @Test
    void joinProducesTheSpaceDelimitedFormTheSpecUses() {
        assertThat(Scopes.join(new java.util.LinkedHashSet<>(java.util.List.of("openid", "profile"))))
                .isEqualTo("openid profile");
    }
}
