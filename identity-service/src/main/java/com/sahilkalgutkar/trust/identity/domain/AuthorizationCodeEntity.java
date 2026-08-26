package com.sahilkalgutkar.trust.identity.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.TenantId;

import java.time.Instant;
import java.util.UUID;

/**
 * A one-time authorization code.
 *
 * <p>Only the SHA-256 of the code is stored. Consumption is recorded rather than deleted, because a
 * deleted code is indistinguishable from a code that never existed — and telling those apart is
 * what lets the token endpoint treat a second presentation as a replay and revoke everything the
 * first presentation produced.
 */
@Entity
@Table(name = "authorization_codes")
public class AuthorizationCodeEntity {

    @Id
    private UUID id;

    @TenantId
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "code_hash", nullable = false)
    private String codeHash;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(nullable = false)
    private String scope;

    private String nonce;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method")
    private String codeChallengeMethod;

    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt = Instant.now();

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected AuthorizationCodeEntity() {
    }

    public AuthorizationCodeEntity(UUID id, String codeHash, String clientId, UUID userId,
                                   String redirectUri, String scope, Instant expiresAt) {
        this.id = id;
        this.codeHash = codeHash;
        this.clientId = clientId;
        this.userId = userId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.expiresAt = expiresAt;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isExpiredAt(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public void consume(Instant at) {
        this.consumedAt = at;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public String getClientId() {
        return clientId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public void setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public void setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }
}
