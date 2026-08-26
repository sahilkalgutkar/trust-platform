package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.common.hash.Tokens;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import com.sahilkalgutkar.trust.identity.audit.AuditRecorder;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.domain.RefreshTokenEntity;
import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.jwt.JwtIssuer;
import com.sahilkalgutkar.trust.identity.repo.AuthorizationCodeRepository;
import com.sahilkalgutkar.trust.identity.repo.RefreshTokenRepository;
import com.sahilkalgutkar.trust.identity.repo.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * The token endpoint: the three supported grants, plus the replay handling that makes them safe.
 *
 * <p>Two rules run through everything below. First, <b>a bearer credential is single use</b> — both
 * authorization codes and refresh tokens are consumed on presentation, and consumption is recorded
 * rather than deleted so a second presentation is distinguishable from a first. Second, <b>a second
 * presentation is treated as a compromise, not a mistake</b>: it revokes the entire lineage of
 * tokens descended from that grant. The legitimate client loses its session and has to log in
 * again, which is a real cost — and the right one, because the alternative is letting an attacker
 * who holds a copy keep refreshing indefinitely while the victim notices nothing.
 */
@Service
public class TokenService {

    private final AuthorizationCodeRepository codeRepository;
    private final CompromiseResponder compromiseResponder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final PkceValidator pkceValidator;
    private final JwtIssuer jwtIssuer;
    private final AuditRecorder auditRecorder;
    private final IdentityProperties properties;
    private final Clock clock;

    public TokenService(AuthorizationCodeRepository codeRepository,
                        CompromiseResponder compromiseResponder,
                        RefreshTokenRepository refreshTokenRepository,
                        UserRepository userRepository,
                        PkceValidator pkceValidator,
                        JwtIssuer jwtIssuer,
                        AuditRecorder auditRecorder,
                        IdentityProperties properties,
                        Clock clock) {
        this.codeRepository = codeRepository;
        this.compromiseResponder = compromiseResponder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.pkceValidator = pkceValidator;
        this.jwtIssuer = jwtIssuer;
        this.auditRecorder = auditRecorder;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public TokenResponse exchange(TokenRequest request, OAuthClientEntity client, String tenantSlug) {
        String grantType = request.grantType();
        if (grantType == null || grantType.isBlank()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST, "grant_type is required");
        }
        if (!client.allowsGrantType(grantType)) {
            throw OAuthException.badRequest(OAuthErrors.UNAUTHORIZED_CLIENT,
                    "This client is not registered for grant_type=" + grantType);
        }
        return switch (grantType) {
            case "authorization_code" -> authorizationCodeGrant(request, client, tenantSlug);
            case "refresh_token" -> refreshTokenGrant(request, client, tenantSlug);
            case "client_credentials" -> clientCredentialsGrant(request, client, tenantSlug);
            default -> throw OAuthException.badRequest(OAuthErrors.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported grant_type");
        };
    }

    private TokenResponse authorizationCodeGrant(TokenRequest request, OAuthClientEntity client,
                                                 String tenantSlug) {
        if (request.code() == null || request.code().isBlank()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST, "code is required");
        }
        AuthorizationCodeEntity code = codeRepository.findByCodeHash(Tokens.hash(request.code()))
                .orElseThrow(() -> OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        Instant now = clock.instant();
        if (code.isConsumed()) {
            // RFC 6749 §4.1.2: a code presented twice must be assumed leaked. Everything the first
            // presentation produced goes with it — the family id of those refresh tokens is the
            // code's own id, precisely so this revocation can find them. It commits separately,
            // because the exception below rolls this transaction back.
            compromiseResponder.revokeFamily(code.getId(), now,
                    AuditEvent.builder(TenantContext.require(), "code.replay_detected")
                            .actor("client:" + client.getClientId())
                            .resource("authorization_code", code.getId().toString())
                            .outcome(AuditOutcome.DENIED)
                            .occurredAt(now)
                            .build());
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        if (code.isExpiredAt(now)) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        if (!code.getClientId().equals(client.getClientId())) {
            // The authenticated client is not the one this code was issued to. Burn it anyway:
            // whoever holds it should not get a second attempt with the right client id.
            compromiseResponder.burnCode(code.getId(), now,
                    AuditEvent.builder(TenantContext.require(), "code.client_mismatch")
                            .actor("client:" + client.getClientId())
                            .resource("authorization_code", code.getId().toString())
                            .outcome(AuditOutcome.DENIED)
                            .occurredAt(now)
                            .build());
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        if (!code.getRedirectUri().equals(request.redirectUri())) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        pkceValidator.verify(code.getCodeChallenge(), code.getCodeChallengeMethod(), request.codeVerifier());

        code.consume(now);
        codeRepository.save(code);

        UserEntity user = userRepository.findById(code.getUserId())
                .filter(UserEntity::isActive)
                .orElseThrow(() -> OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        String issuer = properties.issuerFor(tenantSlug);
        String scope = code.getScope();
        String accessToken = jwtIssuer.issueAccessToken(issuer, user.getId().toString(),
                client.getClientId(), TenantContext.require(), scope, properties.getAccessTokenTtl());
        String idToken = Scopes.parse(scope).contains("openid")
                ? jwtIssuer.issueIdToken(issuer, user.getId().toString(), client.getClientId(),
                TenantContext.require(), user.getEmail(), code.getNonce(), code.getIssuedAt(),
                properties.getAccessTokenTtl())
                : null;
        String refreshToken = client.allowsGrantType("refresh_token")
                ? issueRefreshToken(code.getId(), client.getClientId(), user.getId(), scope, now)
                : null;

        auditRecorder.record(AuditEvent.builder(TenantContext.require(), "token.issued")
                .actor("user:" + user.getId())
                .resource("client", client.getClientId())
                .attribute("grant_type", "authorization_code")
                .attribute("scope", scope)
                .occurredAt(now)
                .build());

        return new TokenResponse(accessToken, "Bearer",
                properties.getAccessTokenTtl().toSeconds(), refreshToken, idToken, scope);
    }

    private TokenResponse refreshTokenGrant(TokenRequest request, OAuthClientEntity client,
                                            String tenantSlug) {
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST, "refresh_token is required");
        }
        RefreshTokenEntity presented = refreshTokenRepository
                .findByTokenHash(Tokens.hash(request.refreshToken()))
                .orElseThrow(() -> OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        Instant now = clock.instant();
        if (presented.getConsumedAt() != null || presented.getRevokedAt() != null) {
            // Someone is replaying a token that has already been rotated away. The provider cannot
            // tell whether this request or the earlier one came from the attacker, so it trusts
            // neither and kills the family — in its own transaction, so the rejection below cannot
            // roll the revocation back.
            compromiseResponder.revokeFamily(presented.getFamilyId(), now,
                    AuditEvent.builder(TenantContext.require(), "refresh.reuse_detected")
                            .actor("client:" + client.getClientId())
                            .resource("refresh_family", presented.getFamilyId().toString())
                            .outcome(AuditOutcome.DENIED)
                            .attribute("user_id", presented.getUserId().toString())
                            .occurredAt(now)
                            .build());
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }
        if (!presented.isUsable(now) || !presented.getClientId().equals(client.getClientId())) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected");
        }

        String scope = Scopes.resolveRefreshed(request.scope(), presented.getScope());
        presented.consume(now);
        refreshTokenRepository.save(presented);

        UserEntity user = userRepository.findById(presented.getUserId())
                .filter(UserEntity::isActive)
                .orElseThrow(() -> OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        String issuer = properties.issuerFor(tenantSlug);
        String accessToken = jwtIssuer.issueAccessToken(issuer, user.getId().toString(),
                client.getClientId(), TenantContext.require(), scope, properties.getAccessTokenTtl());
        String rotated = issueRefreshToken(presented.getFamilyId(), client.getClientId(),
                user.getId(), scope, now);

        auditRecorder.record(AuditEvent.builder(TenantContext.require(), "token.refreshed")
                .actor("user:" + user.getId())
                .resource("client", client.getClientId())
                .attribute("scope", scope)
                .occurredAt(now)
                .build());

        return new TokenResponse(accessToken, "Bearer",
                properties.getAccessTokenTtl().toSeconds(), rotated, null, scope);
    }

    private TokenResponse clientCredentialsGrant(TokenRequest request, OAuthClientEntity client,
                                                 String tenantSlug) {
        if (client.isPublicClient()) {
            // There is nothing to authenticate: a public client presenting no secret would be
            // handing out tokens to anyone who knows a client id.
            throw OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT,
                    "client_credentials requires a confidential client");
        }
        Set<String> registered = client.allowedScopes();
        String scope = Scopes.resolveRequested(request.scope(), registered);
        Instant now = clock.instant();

        String accessToken = jwtIssuer.issueAccessToken(properties.issuerFor(tenantSlug),
                "client:" + client.getClientId(), client.getClientId(), TenantContext.require(),
                scope, properties.getAccessTokenTtl());

        auditRecorder.record(AuditEvent.builder(TenantContext.require(), "token.issued")
                .actor("client:" + client.getClientId())
                .resource("client", client.getClientId())
                .attribute("grant_type", "client_credentials")
                .attribute("scope", scope)
                .occurredAt(now)
                .build());

        // No refresh token: the client can always authenticate again with its own credentials, so
        // a refresh token would be a second, longer-lived credential bought for nothing.
        return new TokenResponse(accessToken, "Bearer",
                properties.getAccessTokenTtl().toSeconds(), null, null, scope);
    }

    private String issueRefreshToken(UUID familyId, String clientId, UUID userId, String scope, Instant now) {
        String raw = Tokens.generate();
        refreshTokenRepository.save(new RefreshTokenEntity(
                UUID.randomUUID(),
                Tokens.hash(raw),
                familyId,
                clientId,
                userId,
                scope,
                now.plus(properties.getRefreshTokenTtl())));
        return raw;
    }

    /** Used by the revocation endpoint: revoking any member revokes the lineage. */
    @Transactional
    public void revokeRefreshToken(String rawToken, OAuthClientEntity client) {
        refreshTokenRepository.findByTokenHash(Tokens.hash(rawToken))
                .filter(token -> token.getClientId().equals(client.getClientId()))
                .ifPresent(token -> {
                    Instant now = clock.instant();
                    compromiseResponder.revokeFamily(token.getFamilyId(), now,
                            AuditEvent.builder(TenantContext.require(), "refresh.revoked")
                                    .actor("client:" + client.getClientId())
                                    .resource("refresh_family", token.getFamilyId().toString())
                                    .occurredAt(now)
                                    .build());
                });
    }
}
