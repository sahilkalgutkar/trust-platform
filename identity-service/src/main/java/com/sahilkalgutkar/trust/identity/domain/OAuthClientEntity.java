package com.sahilkalgutkar.trust.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.TenantId;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/** A registered OAuth client, scoped to the tenant that registered it. */
@Entity
@Table(name = "oauth_clients")
public class OAuthClientEntity {

    @Id
    private UUID id;

    @TenantId
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    /** Null for public clients — an SPA cannot hold a secret, so it proves itself with PKCE. */
    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(nullable = false)
    private String name;

    @Column(name = "redirect_uris", nullable = false)
    private String redirectUris = "";

    @Column(name = "grant_types", nullable = false)
    private String grantTypes = "authorization_code,refresh_token";

    @Column(nullable = false)
    private String scopes = "openid,profile";

    @Column(name = "require_pkce", nullable = false)
    private boolean requirePkce = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    protected OAuthClientEntity() {
    }

    public OAuthClientEntity(UUID id, String clientId, String name) {
        this.id = id;
        this.clientId = clientId;
        this.name = name;
    }

    public boolean isPublicClient() {
        return clientSecretHash == null || clientSecretHash.isBlank();
    }

    /**
     * Exact string match against the registered set — no prefix or wildcard matching, which is the
     * classic open-redirect hole in hand-rolled providers.
     */
    public boolean allowsRedirectUri(String candidate) {
        return candidate != null && csvToSet(redirectUris).contains(candidate);
    }

    public boolean allowsGrantType(String grantType) {
        return csvToSet(grantTypes).contains(grantType);
    }

    public Set<String> allowedScopes() {
        return csvToSet(scopes);
    }

    public Set<String> redirectUriSet() {
        return csvToSet(redirectUris);
    }

    public Set<String> grantTypeSet() {
        return csvToSet(grantTypes);
    }

    static Set<String> csvToSet(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientSecretHash() {
        return clientSecretHash;
    }

    public void setClientSecretHash(String clientSecretHash) {
        this.clientSecretHash = clientSecretHash;
    }

    public String getName() {
        return name;
    }

    public void setRedirectUris(String redirectUris) {
        this.redirectUris = redirectUris;
    }

    public void setGrantTypes(String grantTypes) {
        this.grantTypes = grantTypes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public boolean isRequirePkce() {
        return requirePkce;
    }

    public void setRequirePkce(boolean requirePkce) {
        this.requirePkce = requirePkce;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
