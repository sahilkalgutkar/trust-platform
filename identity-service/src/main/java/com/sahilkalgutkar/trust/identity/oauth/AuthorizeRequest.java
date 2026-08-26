package com.sahilkalgutkar.trust.identity.oauth;

/** The parameters of an RFC 6749 §4.1.1 authorization request. */
public record AuthorizeRequest(
        String responseType,
        String clientId,
        String redirectUri,
        String scope,
        String state,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod) {
}
