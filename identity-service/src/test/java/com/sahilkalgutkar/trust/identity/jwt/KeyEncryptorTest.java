package com.sahilkalgutkar.trust.identity.jwt;

import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeyEncryptorTest {

    private static final byte[] SECRET = "a-private-key-in-pkcs8-form".getBytes(StandardCharsets.UTF_8);

    @Test
    void wrappingThenUnwrappingReturnsTheOriginalBytes() {
        KeyEncryptor encryptor = encryptorWithKey(masterKey((byte) 1));

        assertThat(encryptor.unwrap(encryptor.wrap(SECRET))).isEqualTo(SECRET);
    }

    @Test
    void theCiphertextDoesNotContainThePlaintext() {
        KeyEncryptor encryptor = encryptorWithKey(masterKey((byte) 1));

        assertThat(Base64.getDecoder().decode(encryptor.wrap(SECRET))).isNotEqualTo(SECRET);
    }

    /** A fresh IV per call, so encrypting the same key twice does not produce the same row. */
    @Test
    void wrappingTheSameValueTwiceProducesDifferentCiphertext() {
        KeyEncryptor encryptor = encryptorWithKey(masterKey((byte) 1));

        assertThat(encryptor.wrap(SECRET)).isNotEqualTo(encryptor.wrap(SECRET));
    }

    @Test
    void anotherMasterKeyCannotUnwrapIt() {
        String wrapped = encryptorWithKey(masterKey((byte) 1)).wrap(SECRET);

        assertThatThrownBy(() -> encryptorWithKey(masterKey((byte) 2)).unwrap(wrapped))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("wrong master key or tampered ciphertext");
    }

    /** GCM authenticates: a row edited in the database fails to decrypt rather than yielding junk. */
    @Test
    void tamperedCiphertextIsRejectedRatherThanDecryptedToGarbage() {
        KeyEncryptor encryptor = encryptorWithKey(masterKey((byte) 1));
        byte[] raw = Base64.getDecoder().decode(encryptor.wrap(SECRET));
        raw[raw.length - 1] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(raw);

        assertThatThrownBy(() -> encryptor.unwrap(tampered)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aTruncatedCiphertextIsRejected() {
        KeyEncryptor encryptor = encryptorWithKey(masterKey((byte) 1));

        assertThatThrownBy(() -> encryptor.unwrap(Base64.getEncoder().encodeToString(new byte[8])))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aMasterKeyOfTheWrongLengthIsRejectedAtStartup() {
        IdentityProperties properties = new IdentityProperties();
        properties.setMasterKey(Base64.getEncoder().encodeToString(new byte[16]));

        assertThatThrownBy(() -> new KeyEncryptor(properties))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void anUnconfiguredMasterKeyFallsBackToADeterministicDevelopmentKey() {
        KeyEncryptor first = encryptorWithKey("");
        KeyEncryptor second = encryptorWithKey("");

        assertThat(second.unwrap(first.wrap(SECRET))).isEqualTo(SECRET);
    }

    private static KeyEncryptor encryptorWithKey(String base64Key) {
        IdentityProperties properties = new IdentityProperties();
        properties.setMasterKey(base64Key);
        return new KeyEncryptor(properties);
    }

    private static String masterKey(byte fill) {
        byte[] key = new byte[32];
        java.util.Arrays.fill(key, fill);
        return Base64.getEncoder().encodeToString(key);
    }
}
