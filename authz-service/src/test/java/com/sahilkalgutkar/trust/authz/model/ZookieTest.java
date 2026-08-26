package com.sahilkalgutkar.trust.authz.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ZookieTest {

    @Test
    void aZookieRoundTripsThroughItsEncoding() {
        assertThat(Zookie.decode(Zookie.of(42).encode())).isEqualTo(Zookie.of(42));
    }

    /** Opaque on purpose: nothing outside this service should be reading a revision out of it. */
    @Test
    void theEncodingDoesNotExposeTheRevisionInPlainText() {
        assertThat(Zookie.of(12345).encode()).doesNotContain("12345");
    }

    @Test
    void noZookieMeansTheZeroRevisionRatherThanAnError() {
        assertThat(Zookie.decode(null).revision()).isZero();
        assertThat(Zookie.decode("").revision()).isZero();
    }

    @Test
    void aMalformedTokenIsRejected() {
        assertThatThrownBy(() -> Zookie.decode("not-a-zookie!!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Malformed consistency token");
        assertThatThrownBy(() -> Zookie.decode(java.util.Base64.getUrlEncoder()
                .encodeToString("garbage".getBytes(java.nio.charset.StandardCharsets.UTF_8))))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aNegativeRevisionIsNotARevision() {
        assertThatThrownBy(() -> Zookie.of(-1)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void laterRevisionsEncodeDifferently() {
        assertThat(Zookie.of(1).encode()).isNotEqualTo(Zookie.of(2).encode());
    }
}
