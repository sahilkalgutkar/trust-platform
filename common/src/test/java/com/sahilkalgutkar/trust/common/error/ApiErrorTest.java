package com.sahilkalgutkar.trust.common.error;

import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ApiErrorTest {

    @Test
    void serializesWithTheSnakeCaseNamesRfc6749Requires() {
        String json = CanonicalJson.string(ApiError.of(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        assertThat(json).isEqualTo("{\"error\":\"invalid_grant\",\"error_description\":\"Grant rejected\"}");
    }

    @Test
    void omitsTheDescriptionRatherThanEmittingNull() {
        assertThat(CanonicalJson.string(ApiError.of(OAuthErrors.INVALID_CLIENT, null)))
                .isEqualTo("{\"error\":\"invalid_client\"}");
    }
}
