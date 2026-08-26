package com.sahilkalgutkar.trust.common.error;

/** The RFC 6749 §5.2 / RFC 6750 error codes this platform returns. */
public final class OAuthErrors {

    public static final String INVALID_REQUEST = "invalid_request";
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String INVALID_GRANT = "invalid_grant";
    public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";
    public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
    public static final String INVALID_SCOPE = "invalid_scope";
    public static final String ACCESS_DENIED = "access_denied";
    public static final String SERVER_ERROR = "server_error";

    private OAuthErrors() {
    }
}
