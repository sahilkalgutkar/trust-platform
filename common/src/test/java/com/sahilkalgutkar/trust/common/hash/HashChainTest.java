package com.sahilkalgutkar.trust.common.hash;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HashChainTest {

    private static final Map<String, String> PAYLOAD = Map.of("action", "token.issued");

    @Test
    void genesisIs32ZeroBytes() {
        assertThat(HashChain.GENESIS).hasSize(64).matches("0+");
    }

    @Test
    void linkingIsDeterministic() {
        assertThat(HashChain.link(HashChain.GENESIS, PAYLOAD))
                .isEqualTo(HashChain.link(HashChain.GENESIS, PAYLOAD))
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }

    @Test
    void changingThePayloadChangesTheHash() {
        String original = HashChain.link(HashChain.GENESIS, PAYLOAD);
        String tampered = HashChain.link(HashChain.GENESIS, Map.of("action", "token.revoked"));

        assertThat(tampered).isNotEqualTo(original);
    }

    @Test
    void changingThePredecessorChangesTheHash() {
        String first = HashChain.link(HashChain.GENESIS, PAYLOAD);
        String second = HashChain.link(first, PAYLOAD);
        String rebased = HashChain.link("a".repeat(64), PAYLOAD);

        assertThat(second).isNotEqualTo(rebased);
    }

    @Test
    void editingOneRecordBreaksEveryHashAfterIt() {
        String one = HashChain.link(HashChain.GENESIS, Map.of("seq", "1"));
        String two = HashChain.link(one, Map.of("seq", "2"));
        String three = HashChain.link(two, Map.of("seq", "3"));

        String tamperedTwo = HashChain.link(one, Map.of("seq", "2-edited"));
        String recomputedThree = HashChain.link(tamperedTwo, Map.of("seq", "3"));

        assertThat(recomputedThree).isNotEqualTo(three);
    }

    @Test
    void previousHashIsCaseInsensitive() {
        String lower = HashChain.link("ab".repeat(32), PAYLOAD);
        String upper = HashChain.link("AB".repeat(32), PAYLOAD);

        assertThat(upper).isEqualTo(lower);
    }

    @Test
    void aPreviousHashOfTheWrongLengthIsRejected() {
        assertThatThrownBy(() -> HashChain.link("abc", PAYLOAD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("64 hex characters");
        assertThatThrownBy(() -> HashChain.link(null, PAYLOAD))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullPayloadIsRejected() {
        assertThatThrownBy(() -> HashChain.link(HashChain.GENESIS, (byte[]) null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("canonicalPayload");
    }

    @Test
    void isValidLinkAcceptsTheHashItProduced() {
        String hash = HashChain.link(HashChain.GENESIS, PAYLOAD);

        assertThat(HashChain.isValidLink(HashChain.GENESIS, PAYLOAD, hash)).isTrue();
        assertThat(HashChain.isValidLink(HashChain.GENESIS, PAYLOAD, hash.toUpperCase())).isTrue();
    }

    @Test
    void isValidLinkRejectsATamperedPayload() {
        String hash = HashChain.link(HashChain.GENESIS, PAYLOAD);

        assertThat(HashChain.isValidLink(HashChain.GENESIS, Map.of("action", "other"), hash)).isFalse();
        assertThat(HashChain.isValidLink(HashChain.GENESIS, PAYLOAD, null)).isFalse();
        assertThat(HashChain.isValidLink(HashChain.GENESIS, PAYLOAD, "f".repeat(64))).isFalse();
    }

    @Test
    void constantTimeEqualsMatchesOrdinaryEquality() {
        assertThat(HashChain.constantTimeEquals("abc", "abc")).isTrue();
        assertThat(HashChain.constantTimeEquals("abc", "abd")).isFalse();
        assertThat(HashChain.constantTimeEquals("abc", "abcd")).isFalse();
    }
}
