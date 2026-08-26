package com.sahilkalgutkar.trust.authz.model;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * A consistency token: the storage revision a caller has already observed.
 *
 * <p>This is Zanzibar's answer to the "new enemy" problem. Without it, an application that removes
 * someone from a document and then re-shares it can have a stale cached check let the removed user
 * in — the two operations are ordered in the application, but nothing forces the permission system
 * to observe them in that order. A caller that passes the zookie it got from its write is telling
 * the check "do not answer me from a snapshot older than this", and a cache entry computed before
 * that revision is skipped rather than served.
 *
 * <p>It is deliberately opaque to callers: base64 of {@code r<revision>}, so the encoding can
 * change to a real hybrid-logical timestamp without any client noticing.
 */
public record Zookie(long revision) {

    private static final String PREFIX = "r";

    public Zookie {
        if (revision < 0) {
            throw new IllegalArgumentException("Revision must not be negative");
        }
    }

    public static Zookie of(long revision) {
        return new Zookie(revision);
    }

    public String encode() {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((PREFIX + revision).getBytes(StandardCharsets.UTF_8));
    }

    public static Zookie decode(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            return new Zookie(0);
        }
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
            if (!decoded.startsWith(PREFIX)) {
                throw new IllegalArgumentException("Not a zookie: " + encoded);
            }
            return new Zookie(Long.parseLong(decoded.substring(PREFIX.length())));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Malformed consistency token", e);
        }
    }
}
