package com.sahilkalgutkar.trust.common.hash;

import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokensTest {

    @Test
    void generatedTokensCarry256BitsAndAreUrlSafe() {
        String token = Tokens.generate();

        assertThat(token).hasSize(43).matches("[A-Za-z0-9_-]+");
    }

    @Test
    void generatedTokensDoNotRepeat() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 1_000; i++) {
            seen.add(Tokens.generate());
        }

        assertThat(seen).hasSize(1_000);
    }

    @Test
    void hashingIsDeterministicAndNotTheTokenItself() {
        String token = Tokens.generate();

        assertThat(Tokens.hash(token))
                .isEqualTo(Tokens.hash(token))
                .isNotEqualTo(token)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void differentTokensHashDifferently() {
        assertThat(Tokens.hash("one")).isNotEqualTo(Tokens.hash("two"));
    }

    @Test
    void blankTokensAreRejectedRatherThanHashedToAConstant() {
        assertThatThrownBy(() -> Tokens.hash(""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Tokens.hash(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void matchesComparesAgainstTheStoredHash() {
        String token = Tokens.generate();
        String stored = Tokens.hash(token);

        assertThat(Tokens.matches(token, stored)).isTrue();
        assertThat(Tokens.matches(token, stored.toUpperCase())).isTrue();
        assertThat(Tokens.matches("some-other-token", stored)).isFalse();
    }

    @Test
    void matchesTreatsNullsAsAMismatchRatherThanThrowing() {
        assertThat(Tokens.matches(null, "abc")).isFalse();
        assertThat(Tokens.matches("abc", null)).isFalse();
    }
}
