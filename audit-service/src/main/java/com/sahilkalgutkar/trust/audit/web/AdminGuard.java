package com.sahilkalgutkar.trust.audit.web;

import com.sahilkalgutkar.trust.audit.config.AuditProperties;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Gate on the audit read API. See {@link AuditProperties#getAdminApiKey()} for why it is a key. */
@Component
public class AdminGuard {

    private final AuditProperties properties;

    public AdminGuard(AuditProperties properties) {
        this.properties = properties;
    }

    public void require(String presentedKey) {
        if (presentedKey == null || !MessageDigest.isEqual(
                presentedKey.getBytes(StandardCharsets.UTF_8),
                properties.getAdminApiKey().getBytes(StandardCharsets.UTF_8))) {
            throw new NotAuthorizedException();
        }
    }

    public static class NotAuthorizedException extends RuntimeException {
        public NotAuthorizedException() {
            super("Administrative key required");
        }
    }
}
