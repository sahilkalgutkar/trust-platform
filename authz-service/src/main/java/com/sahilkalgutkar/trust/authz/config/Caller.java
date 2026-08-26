package com.sahilkalgutkar.trust.authz.config;

import java.util.Set;
import java.util.UUID;

/** Who is asking, as proven by their access token. */
public record Caller(String subject, UUID tenantId, Set<String> scopes) {

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
}
