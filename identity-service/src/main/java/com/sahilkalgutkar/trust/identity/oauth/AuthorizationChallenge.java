package com.sahilkalgutkar.trust.identity.oauth;

/**
 * What a validated (but not yet approved) authorization request looks like.
 *
 * <p>A browser-facing deployment renders this as the login and consent screen. Returning it as JSON
 * keeps the interesting half — the validation rules — testable without a template engine and a
 * headless browser standing in the way.
 */
public record AuthorizationChallenge(
        String clientId,
        String clientName,
        String redirectUri,
        String scope,
        String state,
        boolean pkceRequired) {
}
