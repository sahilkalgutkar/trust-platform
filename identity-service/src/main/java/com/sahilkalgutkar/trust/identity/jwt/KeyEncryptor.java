package com.sahilkalgutkar.trust.identity.jwt;

import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Wraps signing private keys with AES-256-GCM before they are written to Postgres.
 *
 * <p>The threat this addresses is narrow and worth stating plainly: a leaked database backup. It
 * does nothing against an attacker who already has the running process, since the process holds the
 * master key — that is what a KMS or an HSM is for, and where the {@code TRUST_MASTER_KEY} lookup
 * would be replaced in a real deployment. GCM rather than CBC so the ciphertext is authenticated:
 * a tampered row fails to decrypt instead of yielding a subtly wrong key.
 */
@Component
public class KeyEncryptor {

    private static final Logger log = LoggerFactory.getLogger(KeyEncryptor.class);
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey masterKey;
    private final SecureRandom random = new SecureRandom();

    public KeyEncryptor(IdentityProperties properties) {
        this.masterKey = resolveMasterKey(properties.getMasterKey());
    }

    public String wrap(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to wrap signing key", e);
        }
    }

    public byte[] unwrap(String wrapped) {
        try {
            byte[] combined = Base64.getDecoder().decode(wrapped);
            if (combined.length <= IV_LENGTH) {
                throw new IllegalArgumentException("Wrapped key is too short to contain an IV");
            }
            byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(combined, IV_LENGTH, combined.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to unwrap signing key — wrong master key or tampered ciphertext", e);
        }
    }

    private static SecretKey resolveMasterKey(String configured) {
        if (configured != null && !configured.isBlank()) {
            byte[] raw = Base64.getDecoder().decode(configured.trim());
            if (raw.length != 32) {
                throw new IllegalStateException("trust.identity.master-key must decode to 32 bytes (AES-256)");
            }
            return new SecretKeySpec(raw, "AES");
        }
        log.warn("No trust.identity.master-key configured — deriving an ephemeral development key. "
                + "Signing keys wrapped with it are NOT recoverable by another instance. Set "
                + "TRUST_MASTER_KEY before running anything you care about.");
        return new SecretKeySpec(sha256("trust-platform-local-development-master-key"), "AES");
    }

    private static byte[] sha256(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
