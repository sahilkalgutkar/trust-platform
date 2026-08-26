package com.sahilkalgutkar.trust.identity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Tunables for the provider. The defaults are the conservative end of what the OAuth security BCP
 * recommends: short-lived access tokens, one-minute authorization codes, refresh tokens that expire
 * even if never used.
 */
@ConfigurationProperties(prefix = "trust.identity")
public class IdentityProperties {

    /** Base URL the issuer is derived from: {@code {base}/t/{tenant}}. */
    private String issuerBaseUrl = "http://localhost:8081";

    private Duration accessTokenTtl = Duration.ofMinutes(15);

    private Duration refreshTokenTtl = Duration.ofDays(30);

    /** RFC 6749 §4.1.2 puts the ceiling at ten minutes; one is plenty for a browser redirect. */
    private Duration authorizationCodeTtl = Duration.ofMinutes(1);

    /**
     * How long a retired signing key stays published in JWKS. Must exceed the access token TTL, or
     * rotation would invalidate tokens that have not expired yet.
     */
    private Duration retiredKeyGracePeriod = Duration.ofHours(24);

    /** Shared secret for the administrative endpoints. Real deployments front these with mTLS. */
    private String adminApiKey = "local-dev-admin-key";

    /** Base64 AES-256 key that wraps signing private keys at rest. */
    private String masterKey = "";

    private boolean auditPublishingEnabled = true;

    public String issuerFor(String tenantSlug) {
        String base = issuerBaseUrl.endsWith("/")
                ? issuerBaseUrl.substring(0, issuerBaseUrl.length() - 1)
                : issuerBaseUrl;
        return base + "/t/" + tenantSlug;
    }

    public String getIssuerBaseUrl() {
        return issuerBaseUrl;
    }

    public void setIssuerBaseUrl(String issuerBaseUrl) {
        this.issuerBaseUrl = issuerBaseUrl;
    }

    public Duration getAccessTokenTtl() {
        return accessTokenTtl;
    }

    public void setAccessTokenTtl(Duration accessTokenTtl) {
        this.accessTokenTtl = accessTokenTtl;
    }

    public Duration getRefreshTokenTtl() {
        return refreshTokenTtl;
    }

    public void setRefreshTokenTtl(Duration refreshTokenTtl) {
        this.refreshTokenTtl = refreshTokenTtl;
    }

    public Duration getAuthorizationCodeTtl() {
        return authorizationCodeTtl;
    }

    public void setAuthorizationCodeTtl(Duration authorizationCodeTtl) {
        this.authorizationCodeTtl = authorizationCodeTtl;
    }

    public Duration getRetiredKeyGracePeriod() {
        return retiredKeyGracePeriod;
    }

    public void setRetiredKeyGracePeriod(Duration retiredKeyGracePeriod) {
        this.retiredKeyGracePeriod = retiredKeyGracePeriod;
    }

    public String getAdminApiKey() {
        return adminApiKey;
    }

    public void setAdminApiKey(String adminApiKey) {
        this.adminApiKey = adminApiKey;
    }

    public String getMasterKey() {
        return masterKey;
    }

    public void setMasterKey(String masterKey) {
        this.masterKey = masterKey;
    }

    public boolean isAuditPublishingEnabled() {
        return auditPublishingEnabled;
    }

    public void setAuditPublishingEnabled(boolean auditPublishingEnabled) {
        this.auditPublishingEnabled = auditPublishingEnabled;
    }
}
