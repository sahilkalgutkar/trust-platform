package com.sahilkalgutkar.trust.common.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Generation and one-way hashing for bearer credentials (authorization codes, refresh tokens).
 *
 * <p>Nothing here is ever stored in the form it is handed to a client. The database holds the
 * SHA-256 of the token, so a dump of {@code refresh_tokens} yields nothing replayable — the same
 * reasoning as password hashing, minus the work factor, which these do not need: unlike a password
 * these are 256 bits of {@link SecureRandom} output, so there is no dictionary to run against them.
 */
public final class Tokens {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private Tokens() {
    }

    /** 256 bits of entropy, URL-safe — long enough that guessing is not a threat model. */
    public static String generate() {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        return URL_ENCODER.encodeToString(raw);
    }

    public static String hash(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("rawToken must not be blank");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every JRE", e);
        }
    }

    public static boolean matches(String rawToken, String storedHash) {
        if (rawToken == null || storedHash == null) {
            return false;
        }
        return HashChain.constantTimeEquals(hash(rawToken), storedHash.toLowerCase());
    }
}
