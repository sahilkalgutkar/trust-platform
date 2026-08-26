package com.sahilkalgutkar.trust.authz.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "trust.authz")
public class AuthzProperties {

    /**
     * How deep a single check may recurse before giving up.
     *
     * <p>There is a limit at all because a namespace can legitimately describe an unbounded chain
     * — folders inside folders — and a misconfiguration can describe an infinite one. Cycles are
     * caught separately and exactly; this bound is for the merely very deep, where the right
     * answer is to fail loudly rather than tie up a connection walking a thousand levels.
     */
    private int maxDepth = 16;

    private boolean cacheEnabled = true;

    private Duration cacheTtl = Duration.ofSeconds(30);

    /**
     * Base URL that access tokens name as their issuer — the value compared against the {@code iss}
     * claim. This is an identity, not an address: it must match what the identity service stamps
     * into tokens, byte for byte.
     */
    private String issuerBaseUrl = "http://localhost:8081";

    /**
     * Where this service actually fetches JWKS from, when that differs from the issuer.
     *
     * <p>It usually does. The issuer is a stable public URL that clients and tokens agree on
     * ({@code https://id.example.com}), while service-to-service traffic goes over an internal
     * address ({@code http://identity-service:8081}) that never appears in a token. Conflating the
     * two works right up until the first deployment where they differ — and then every token fails
     * verification for a reason that looks nothing like a networking problem. Defaults to
     * {@link #issuerBaseUrl} when unset, which is correct for a single-host setup.
     */
    private String jwksBaseUrl = "";

    /** Where this service fetches the signing keys it verifies access tokens against. */
    private Duration jwksCacheTtl = Duration.ofMinutes(10);

    private boolean auditPublishingEnabled = true;

    public String issuerFor(String tenantSlug) {
        return trimTrailingSlash(issuerBaseUrl) + "/t/" + tenantSlug;
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public String jwksUriFor(String tenantSlug) {
        String base = jwksBaseUrl == null || jwksBaseUrl.isBlank() ? issuerBaseUrl : jwksBaseUrl;
        return trimTrailingSlash(base) + "/t/" + tenantSlug + "/oauth2/jwks";
    }

    public int getMaxDepth() {
        return maxDepth;
    }

    public void setMaxDepth(int maxDepth) {
        this.maxDepth = maxDepth;
    }

    public boolean isCacheEnabled() {
        return cacheEnabled;
    }

    public void setCacheEnabled(boolean cacheEnabled) {
        this.cacheEnabled = cacheEnabled;
    }

    public Duration getCacheTtl() {
        return cacheTtl;
    }

    public void setCacheTtl(Duration cacheTtl) {
        this.cacheTtl = cacheTtl;
    }

    public String getIssuerBaseUrl() {
        return issuerBaseUrl;
    }

    public void setIssuerBaseUrl(String issuerBaseUrl) {
        this.issuerBaseUrl = issuerBaseUrl;
    }

    public String getJwksBaseUrl() {
        return jwksBaseUrl;
    }

    public void setJwksBaseUrl(String jwksBaseUrl) {
        this.jwksBaseUrl = jwksBaseUrl;
    }

    public Duration getJwksCacheTtl() {
        return jwksCacheTtl;
    }

    public void setJwksCacheTtl(Duration jwksCacheTtl) {
        this.jwksCacheTtl = jwksCacheTtl;
    }

    public boolean isAuditPublishingEnabled() {
        return auditPublishingEnabled;
    }

    public void setAuditPublishingEnabled(boolean auditPublishingEnabled) {
        this.auditPublishingEnabled = auditPublishingEnabled;
    }
}
