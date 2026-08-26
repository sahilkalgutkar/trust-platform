package com.sahilkalgutkar.trust.identity.oauth;

/** The form parameters of an RFC 6749 §3.2 token request. */
public record TokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String codeVerifier,
        String refreshToken,
        String scope) {
}
