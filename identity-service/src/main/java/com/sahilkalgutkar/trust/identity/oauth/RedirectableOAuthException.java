package com.sahilkalgutkar.trust.identity.oauth;

import org.springframework.http.HttpStatus;

/**
 * An authorization error that RFC 6749 §4.1.2.1 says must be reported back to the client by
 * redirecting, rather than rendered to the user.
 *
 * <p>The distinction is a security boundary, not a formatting preference. Errors about the
 * {@code client_id} or {@code redirect_uri} may <em>never</em> redirect — redirecting to an
 * unverified URI to report that the URI is unverified is an open redirect. Everything after those
 * two checks pass is safe to report to an address already proven to belong to the client.
 */
public class RedirectableOAuthException extends OAuthException {

    private final String redirectUri;
    private final String state;

    public RedirectableOAuthException(String error, String description, String redirectUri, String state) {
        super(error, description, HttpStatus.FOUND);
        this.redirectUri = redirectUri;
        this.state = state;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }
}
