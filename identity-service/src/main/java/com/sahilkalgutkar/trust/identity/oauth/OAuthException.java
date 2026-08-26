package com.sahilkalgutkar.trust.identity.oauth;

import org.springframework.http.HttpStatus;

/**
 * A protocol-level failure, carrying the RFC 6749 error code the caller should see.
 *
 * <p>The description is intentionally coarse. "Invalid grant" covers an unknown code, an expired
 * code, a code belonging to a different client, and a failed PKCE check — telling those apart would
 * hand an attacker a free oracle for probing which half of a guess was right.
 */
public class OAuthException extends RuntimeException {

    private final String error;
    private final HttpStatus status;

    public OAuthException(String error, String description, HttpStatus status) {
        super(description);
        this.error = error;
        this.status = status;
    }

    public static OAuthException badRequest(String error, String description) {
        return new OAuthException(error, description, HttpStatus.BAD_REQUEST);
    }

    public static OAuthException unauthorized(String error, String description) {
        return new OAuthException(error, description, HttpStatus.UNAUTHORIZED);
    }

    public String getError() {
        return error;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
