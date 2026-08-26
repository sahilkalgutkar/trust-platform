package com.sahilkalgutkar.trust.identity.oauth;

/** The authorization code and where to send the user agent with it. */
public record IssuedCode(String code, String redirectUri, String state) {
}
