package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * RFC 7636 proof key for code exchange.
 *
 * <p>PKCE is what makes an intercepted authorization code useless: the code alone is not enough
 * without the verifier whose hash was committed to at the start of the flow. Two rules matter here
 * beyond the obvious hash comparison:
 *
 * <ul>
 *   <li>{@code plain} is accepted only when the client registered a plain challenge — an attacker
 *       who can intercept the code can also rewrite {@code code_challenge_method} to {@code plain}
 *       and supply the challenge as the verifier, so the method is taken from what was <em>stored
 *       at authorization time</em>, never from the token request.</li>
 *   <li>A client that registered a challenge must present a verifier. Treating a missing verifier
 *       as "no PKCE required" would let the whole mechanism be skipped by omitting a parameter.</li>
 * </ul>
 */
@Component
public class PkceValidator {

    public static final String METHOD_S256 = "S256";
    public static final String METHOD_PLAIN = "plain";

    /** RFC 7636 §4.1: 43–128 characters from the unreserved set. */
    private static final Pattern VERIFIER = Pattern.compile("[A-Za-z0-9\\-._~]{43,128}");

    public void validateChallenge(String challenge, String method) {
        if (challenge == null || challenge.isBlank()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST,
                    "code_challenge is required for this client");
        }
        if (method != null && !METHOD_S256.equals(method) && !METHOD_PLAIN.equals(method)) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST,
                    "code_challenge_method must be S256 or plain");
        }
    }

    /**
     * @param storedChallenge the challenge captured when the code was issued, or null if the flow
     *                        was started without PKCE
     * @param storedMethod    the method captured at the same time — never the one in the token request
     */
    public void verify(String storedChallenge, String storedMethod, String presentedVerifier) {
        if (storedChallenge == null || storedChallenge.isBlank()) {
            if (presentedVerifier != null && !presentedVerifier.isBlank()) {
                throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT,
                        "Grant rejected");
            }
            return;
        }
        if (presentedVerifier == null || !VERIFIER.matcher(presentedVerifier).matches()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        String expected = METHOD_PLAIN.equals(storedMethod)
                ? presentedVerifier
                : sha256Base64Url(presentedVerifier);
        if (!constantTimeEquals(expected, storedChallenge)) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
    }

    public static String sha256Base64Url(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every JRE", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < a.length(); i++) {
            difference |= a.charAt(i) ^ b.charAt(i);
        }
        return difference == 0;
    }
}
