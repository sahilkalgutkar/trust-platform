package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AdminGuardTest {

    private final IdentityProperties properties = new IdentityProperties();
    private final AdminGuard guard = new AdminGuard(properties);

    @Test
    void theConfiguredKeyIsAccepted() {
        properties.setAdminApiKey("s3cret");

        assertThatCode(() -> guard.require("s3cret")).doesNotThrowAnyException();
    }

    @Test
    void aWrongOrAbsentKeyIsRejected() {
        properties.setAdminApiKey("s3cret");

        assertThatThrownBy(() -> guard.require("wrong")).isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> guard.require(null)).isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> guard.require("")).isInstanceOf(OAuthException.class);
    }

    /** A prefix of the real key must not pass — length is part of the comparison. */
    @Test
    void aPrefixOfTheKeyIsRejected() {
        properties.setAdminApiKey("s3cret");

        assertThatThrownBy(() -> guard.require("s3c")).isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> guard.require("s3cret-and-more")).isInstanceOf(OAuthException.class);
    }
}
