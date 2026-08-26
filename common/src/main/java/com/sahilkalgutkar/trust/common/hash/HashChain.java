package com.sahilkalgutkar.trust.common.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 hash chaining for the audit log.
 *
 * <p>Each record's hash covers both its own canonical bytes and the hash of the record before it,
 * so an attacker with write access to the audit table cannot quietly edit or delete one row: every
 * hash after the edited row stops matching, and {@code AuditVerifier} reports the exact sequence
 * number where the chain breaks. It does not make the log unforgeable — someone who can rewrite the
 * whole table can recompute the whole chain — which is why the chain head is also published to
 * Kafka, where a rewrite of the database cannot reach it.
 */
public final class HashChain {

    /** The hash a tenant's first record chains from: 32 zero bytes. */
    public static final String GENESIS = "0".repeat(64);

    private HashChain() {
    }

    public static String link(String previousHashHex, byte[] canonicalPayload) {
        if (previousHashHex == null || previousHashHex.length() != 64) {
            throw new IllegalArgumentException("previousHashHex must be 64 hex characters");
        }
        if (canonicalPayload == null) {
            throw new IllegalArgumentException("canonicalPayload must not be null");
        }
        MessageDigest digest = sha256();
        digest.update(previousHashHex.toLowerCase().getBytes(StandardCharsets.US_ASCII));
        digest.update((byte) '\n');
        digest.update(canonicalPayload);
        return HexFormat.of().formatHex(digest.digest());
    }

    public static String link(String previousHashHex, Object payload) {
        return link(previousHashHex, CanonicalJson.bytes(payload));
    }

    public static boolean isValidLink(String previousHashHex, Object payload, String expectedHashHex) {
        if (expectedHashHex == null) {
            return false;
        }
        return constantTimeEquals(link(previousHashHex, payload), expectedHashHex.toLowerCase());
    }

    /**
     * Compares in constant time. The comparison is over a public hash rather than a secret, so this
     * is belt-and-braces — but a verification endpoint that returns faster on an early mismatch
     * still leaks how much of a forged chain was accepted, and there is no reason to leak it.
     */
    static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length(); i++) {
            difference |= a.charAt(i) ^ b.charAt(i);
        }
        return difference == 0;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every JRE", e);
        }
    }
}
