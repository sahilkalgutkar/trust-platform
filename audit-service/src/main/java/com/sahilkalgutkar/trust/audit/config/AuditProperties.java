package com.sahilkalgutkar.trust.audit.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "trust.audit")
public class AuditProperties {

    /**
     * Shared secret for the read API.
     *
     * <p>Unlike the authorization service, this one does not accept end-user access tokens. Its
     * audience is operators and compliance readers rather than application clients, and it sits
     * behind the platform's internal gateway — issuing every application a token that could read the
     * audit log would widen the blast radius of any one of them being compromised, for no benefit.
     */
    private String adminApiKey = "local-dev-admin-key";

    private int maxPageSize = 200;

    public String getAdminApiKey() {
        return adminApiKey;
    }

    public void setAdminApiKey(String adminApiKey) {
        this.adminApiKey = adminApiKey;
    }

    public int getMaxPageSize() {
        return maxPageSize;
    }

    public void setMaxPageSize(int maxPageSize) {
        this.maxPageSize = maxPageSize;
    }
}
