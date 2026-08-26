package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TokenServiceTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private static final String CHALLENGE = PkceValidator.sha256Base64Url(VERIFIER);

    private final AuthorizationCodeRepository codeRepository = mock(AuthorizationCodeRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final JwtIssuer jwtIssuer = mock(JwtIssuer.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final IdentityProperties properties = new IdentityProperties();

    private InMemoryRefreshTokenRepository refreshTokens;
    private TokenService tokenService;
    private UserEntity user;
    private OAuthClientEntity client;

    @BeforeEach
    void setUp() {
        TenantContext.set(TENANT);
        refreshTokens = new InMemoryRefreshTokenRepository();
        // The responder is wired with the same fakes rather than mocked: what these tests assert
        // is that a replay revokes the family, and a mock would just agree that it was asked to.
        tokenService = new TokenService(codeRepository,
                new CompromiseResponder(refreshTokens, codeRepository, auditRecorder),
                refreshTokens, userRepository,
                new PkceValidator(), jwtIssuer, auditRecorder, properties,
                Clock.fixed(NOW, ZoneOffset.UTC));

        user = new UserEntity(UUID.randomUUID(), "ada@acme.test", "hash");
        client = new OAuthClientEntity(UUID.randomUUID(), "web-app", "Web App");
        client.setClientSecretHash("$2a$10$hash");
        client.setGrantTypes("authorization_code,refresh_token");
        client.setScopes("openid,profile");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(jwtIssuer.issueAccessToken(anyString(), anyString(), anyString(), anyString(), anyString(), any()))
                .thenReturn("access-token");
        when(jwtIssuer.issueIdToken(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any())).thenReturn("id-token");
    }

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    // ---------------------------------------------------------------- authorization_code

    @Test
    void aValidCodeIsExchangedForTokens() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));

        TokenResponse response = tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.idToken()).isEqualTo("id-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
        assertThat(response.scope()).isEqualTo("openid profile");
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void theCodeIsConsumedSoItCannotBeUsedTwice() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));

        tokenService.exchange(codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme");

        ArgumentCaptor<AuthorizationCodeEntity> saved = ArgumentCaptor.forClass(AuthorizationCodeEntity.class);
        verify(codeRepository).save(saved.capture());
        assertThat(saved.getValue().isConsumed()).isTrue();
    }

    @Test
    void noIdTokenIsIssuedWithoutTheOpenidScope() {
        AuthorizationCodeEntity code = code(NOW.plusSeconds(60), "profile");
        String rawCode = givenStoredCode(code);

        TokenResponse response = tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme");

        assertThat(response.idToken()).isNull();
    }

    /**
     * The headline behaviour: replaying a code does not merely fail, it destroys everything the
     * first (possibly legitimate) exchange produced.
     */
    @Test
    void replayingAConsumedCodeRevokesEveryTokenItProduced() {
        AuthorizationCodeEntity code = code(NOW.plusSeconds(60));
        String rawCode = givenStoredCode(code);
        tokenService.exchange(codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme");
        RefreshTokenEntity issued = refreshTokens.findAll().get(0);
        assertThat(issued.getRevokedAt()).isNull();

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessage("Grant rejected");

        assertThat(issued.getRevokedAt()).isEqualTo(NOW);
        assertThat(recordedActions()).contains("code.replay_detected");
    }

    @Test
    void anExpiredCodeIsRejected() {
        String rawCode = givenStoredCode(code(NOW.minusSeconds(1)));

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void anUnknownCodeIsRejected() {
        when(codeRepository.findByCodeHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest("nope", "https://app.acme.test/callback", VERIFIER), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aMissingCodeParameterIsRejectedBeforeAnyLookup() {
        assertThatThrownBy(() -> tokenService.exchange(
                new TokenRequest("authorization_code", null, "https://app.acme.test/callback", VERIFIER, null, null),
                client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("code is required");
    }

    /** The confused deputy: a second registered client trying to redeem someone else's code. */
    @Test
    void aCodeIssuedToAnotherClientIsRejectedAndBurned() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));
        OAuthClientEntity attacker = new OAuthClientEntity(UUID.randomUUID(), "evil-app", "Evil App");
        attacker.setClientSecretHash("$2a$10$hash");
        attacker.setGrantTypes("authorization_code,refresh_token");

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), attacker, "acme"))
                .isInstanceOf(OAuthException.class);

        ArgumentCaptor<AuthorizationCodeEntity> saved = ArgumentCaptor.forClass(AuthorizationCodeEntity.class);
        verify(codeRepository).save(saved.capture());
        assertThat(saved.getValue().isConsumed()).isTrue();
        assertThat(recordedActions()).contains("code.client_mismatch");
        // Burning the code is what stops a retry with the correct client id from succeeding.
    }

    @Test
    void aRedirectUriThatDiffersFromTheOneInTheAuthorizationRequestIsRejected() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/other", VERIFIER), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aWrongPkceVerifierIsRejected() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aCodeForADeactivatedUserIsRejected() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));
        user.setStatus("DISABLED");

        assertThatThrownBy(() -> tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void noRefreshTokenIsIssuedToAClientNotRegisteredForThatGrant() {
        client.setGrantTypes("authorization_code");
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));

        TokenResponse response = tokenService.exchange(
                codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER), client, "acme");

        assertThat(response.refreshToken()).isNull();
    }

    // ---------------------------------------------------------------- refresh_token

    @Test
    void refreshingRotatesTheTokenAndConsumesTheOldOne() {
        String original = givenIssuedRefreshToken();

        TokenResponse response = tokenService.exchange(refreshRequest(original, null), client, "acme");

        assertThat(response.refreshToken()).isNotBlank().isNotEqualTo(original);
        assertThat(refreshTokens.findByTokenHash(Tokens.hash(original)).orElseThrow().getConsumedAt())
                .isEqualTo(NOW);
    }

    @Test
    void theRotatedTokenStaysInTheSameFamily() {
        String original = givenIssuedRefreshToken();
        UUID family = refreshTokens.findByTokenHash(Tokens.hash(original)).orElseThrow().getFamilyId();

        TokenResponse response = tokenService.exchange(refreshRequest(original, null), client, "acme");

        assertThat(refreshTokens.findByTokenHash(Tokens.hash(response.refreshToken())).orElseThrow()
                .getFamilyId()).isEqualTo(family);
    }

    /** Token theft, as it actually plays out: the thief refreshes after the victim already did. */
    @Test
    void presentingAnAlreadyRotatedTokenRevokesTheWholeFamily() {
        String stolen = givenIssuedRefreshToken();
        TokenResponse legitimate = tokenService.exchange(refreshRequest(stolen, null), client, "acme");

        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(stolen, null), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessage("Grant rejected");

        assertThat(refreshTokens.findByTokenHash(Tokens.hash(legitimate.refreshToken())).orElseThrow()
                .getRevokedAt()).isEqualTo(NOW);
        assertThat(recordedActions()).contains("refresh.reuse_detected");
    }

    @Test
    void aRevokedTokenCannotBeRefreshed() {
        String token = givenIssuedRefreshToken();
        refreshTokens.findByTokenHash(Tokens.hash(token)).orElseThrow().revoke(NOW);

        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(token, null), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void anExpiredRefreshTokenIsRejected() {
        String token = "expired-token";
        refreshTokens.save(new RefreshTokenEntity(UUID.randomUUID(), Tokens.hash(token), UUID.randomUUID(),
                "web-app", user.getId(), "openid", NOW.minusSeconds(1)));

        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(token, null), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aRefreshTokenBelongingToAnotherClientIsRejected() {
        String token = "other-clients-token";
        refreshTokens.save(new RefreshTokenEntity(UUID.randomUUID(), Tokens.hash(token), UUID.randomUUID(),
                "other-app", user.getId(), "openid", NOW.plusSeconds(3600)));

        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(token, null), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void anUnknownRefreshTokenIsRejected() {
        assertThatThrownBy(() -> tokenService.exchange(refreshRequest("nope", null), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aMissingRefreshTokenParameterIsRejected() {
        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(null, null), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("refresh_token is required");
    }

    @Test
    void aRefreshMayNarrowScopeButNotWidenIt() {
        String token = givenIssuedRefreshToken();

        assertThat(tokenService.exchange(refreshRequest(token, "openid"), client, "acme").scope())
                .isEqualTo("openid");

        String next = givenIssuedRefreshToken();
        assertThatThrownBy(() -> tokenService.exchange(refreshRequest(next, "openid admin"), client, "acme"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void revokingAnyMemberRevokesTheLineage() {
        String token = givenIssuedRefreshToken();

        tokenService.revokeRefreshToken(token, client);

        assertThat(refreshTokens.findByTokenHash(Tokens.hash(token)).orElseThrow().getRevokedAt())
                .isEqualTo(NOW);
        assertThat(recordedActions()).contains("refresh.revoked");
    }

    @Test
    void revokingAnotherClientsTokenDoesNothing() {
        String token = "other-clients-token";
        refreshTokens.save(new RefreshTokenEntity(UUID.randomUUID(), Tokens.hash(token), UUID.randomUUID(),
                "other-app", user.getId(), "openid", NOW.plusSeconds(3600)));

        tokenService.revokeRefreshToken(token, client);

        assertThat(refreshTokens.findByTokenHash(Tokens.hash(token)).orElseThrow().getRevokedAt()).isNull();
        verify(auditRecorder, never()).record(any());
    }

    // ---------------------------------------------------------------- client_credentials

    @Test
    void aConfidentialClientGetsAnAccessTokenAndNoRefreshToken() {
        client.setGrantTypes("client_credentials");

        TokenResponse response = tokenService.exchange(
                new TokenRequest("client_credentials", null, null, null, null, "openid"), client, "acme");

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isNull();
        assertThat(response.idToken()).isNull();
        assertThat(response.scope()).isEqualTo("openid");
    }

    @Test
    void aPublicClientCannotUseClientCredentials() {
        OAuthClientEntity publicClient = new OAuthClientEntity(UUID.randomUUID(), "spa", "SPA");
        publicClient.setGrantTypes("client_credentials");

        assertThatThrownBy(() -> tokenService.exchange(
                new TokenRequest("client_credentials", null, null, null, null, null), publicClient, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("confidential client");
    }

    // ---------------------------------------------------------------- grant dispatch

    @Test
    void aGrantTypeTheClientIsNotRegisteredForIsRejected() {
        assertThatThrownBy(() -> tokenService.exchange(
                new TokenRequest("client_credentials", null, null, null, null, null), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("not registered for grant_type");
    }

    @Test
    void anUnknownGrantTypeIsRejected() {
        client.setGrantTypes("password");

        assertThatThrownBy(() -> tokenService.exchange(
                new TokenRequest("password", null, null, null, null, null), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("Unsupported grant_type");
    }

    @Test
    void aMissingGrantTypeIsRejected() {
        assertThatThrownBy(() -> tokenService.exchange(
                new TokenRequest(null, null, null, null, null, null), client, "acme"))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("grant_type is required");
    }

    // ---------------------------------------------------------------- helpers

    private AuthorizationCodeEntity code(Instant expiresAt) {
        return code(expiresAt, "openid profile");
    }

    private AuthorizationCodeEntity code(Instant expiresAt, String scope) {
        AuthorizationCodeEntity code = new AuthorizationCodeEntity(UUID.randomUUID(), "hash", "web-app",
                user.getId(), "https://app.acme.test/callback", scope, expiresAt);
        code.setCodeChallenge(CHALLENGE);
        code.setCodeChallengeMethod(PkceValidator.METHOD_S256);
        return code;
    }

    private String givenStoredCode(AuthorizationCodeEntity code) {
        String raw = Tokens.generate();
        when(codeRepository.findByCodeHash(Tokens.hash(raw))).thenReturn(Optional.of(code));
        when(codeRepository.findById(code.getId())).thenReturn(Optional.of(code));
        return raw;
    }

    private String givenIssuedRefreshToken() {
        String rawCode = givenStoredCode(code(NOW.plusSeconds(60)));
        return tokenService.exchange(codeRequest(rawCode, "https://app.acme.test/callback", VERIFIER),
                client, "acme").refreshToken();
    }

    private static TokenRequest codeRequest(String code, String redirectUri, String verifier) {
        return new TokenRequest("authorization_code", code, redirectUri, verifier, null, null);
    }

    private static TokenRequest refreshRequest(String refreshToken, String scope) {
        return new TokenRequest("refresh_token", null, null, null, refreshToken, scope);
    }

    private List<String> recordedActions() {
        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditRecorder, org.mockito.Mockito.atLeastOnce()).record(captor.capture());
        return captor.getAllValues().stream().map(AuditEvent::action).toList();
    }

    /**
     * A hand-rolled fake rather than a mock: these tests care about what the store <em>contains</em>
     * after a rotation or a family revocation, and stubbing that with {@code when(...)} chains would
     * describe the assertions rather than exercise them.
     */
    private static final class InMemoryRefreshTokenRepository
            implements RefreshTokenRepository {

        private final Map<UUID, RefreshTokenEntity> byId = new ConcurrentHashMap<>();

        @Override
        public Optional<RefreshTokenEntity> findByTokenHash(String tokenHash) {
            return byId.values().stream().filter(t -> t.getTokenHash().equals(tokenHash)).findFirst();
        }

        @Override
        public List<RefreshTokenEntity> findAllByFamilyId(UUID familyId) {
            return byId.values().stream().filter(t -> t.getFamilyId().equals(familyId)).toList();
        }

        @Override
        public <S extends RefreshTokenEntity> S save(S entity) {
            byId.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public <S extends RefreshTokenEntity> List<S> saveAll(Iterable<S> entities) {
            List<S> saved = new ArrayList<>();
            entities.forEach(e -> {
                save(e);
                saved.add(e);
            });
            return saved;
        }

        @Override
        public List<RefreshTokenEntity> findAll() {
            return List.copyOf(byId.values());
        }

        // The rest of the JpaRepository surface is unused by TokenService.
        @Override
        public void flush() {
        }

        @Override
        public <S extends RefreshTokenEntity> S saveAndFlush(S entity) {
            return save(entity);
        }

        @Override
        public <S extends RefreshTokenEntity> List<S> saveAllAndFlush(Iterable<S> entities) {
            return saveAll(entities);
        }

        @Override
        public void deleteAllInBatch(Iterable<RefreshTokenEntity> entities) {
        }

        @Override
        public void deleteAllByIdInBatch(Iterable<UUID> ids) {
        }

        @Override
        public void deleteAllInBatch() {
        }

        @Override
        public RefreshTokenEntity getOne(UUID id) {
            return byId.get(id);
        }

        @Override
        public RefreshTokenEntity getById(UUID id) {
            return byId.get(id);
        }

        @Override
        public RefreshTokenEntity getReferenceById(UUID id) {
            return byId.get(id);
        }

        @Override
        public <S extends RefreshTokenEntity> Optional<S> findOne(org.springframework.data.domain.Example<S> example) {
            return Optional.empty();
        }

        @Override
        public <S extends RefreshTokenEntity> List<S> findAll(org.springframework.data.domain.Example<S> example) {
            return List.of();
        }

        @Override
        public <S extends RefreshTokenEntity> List<S> findAll(org.springframework.data.domain.Example<S> example,
                                                              org.springframework.data.domain.Sort sort) {
            return List.of();
        }

        @Override
        public <S extends RefreshTokenEntity> org.springframework.data.domain.Page<S> findAll(
                org.springframework.data.domain.Example<S> example,
                org.springframework.data.domain.Pageable pageable) {
            return org.springframework.data.domain.Page.empty();
        }

        @Override
        public <S extends RefreshTokenEntity> long count(org.springframework.data.domain.Example<S> example) {
            return 0;
        }

        @Override
        public <S extends RefreshTokenEntity> boolean exists(org.springframework.data.domain.Example<S> example) {
            return false;
        }

        @Override
        public <S extends RefreshTokenEntity, R> R findBy(org.springframework.data.domain.Example<S> example,
                                                          java.util.function.Function<org.springframework.data.repository.query.FluentQuery.FetchableFluentQuery<S>, R> queryFunction) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<RefreshTokenEntity> findAll(org.springframework.data.domain.Sort sort) {
            return findAll();
        }

        @Override
        public org.springframework.data.domain.Page<RefreshTokenEntity> findAll(
                org.springframework.data.domain.Pageable pageable) {
            return org.springframework.data.domain.Page.empty();
        }

        @Override
        public List<RefreshTokenEntity> findAllById(Iterable<UUID> ids) {
            return List.of();
        }

        @Override
        public Optional<RefreshTokenEntity> findById(UUID id) {
            return Optional.ofNullable(byId.get(id));
        }

        @Override
        public boolean existsById(UUID id) {
            return byId.containsKey(id);
        }

        @Override
        public long count() {
            return byId.size();
        }

        @Override
        public void deleteById(UUID id) {
            byId.remove(id);
        }

        @Override
        public void delete(RefreshTokenEntity entity) {
            byId.remove(entity.getId());
        }

        @Override
        public void deleteAllById(Iterable<? extends UUID> ids) {
        }

        @Override
        public void deleteAll(Iterable<? extends RefreshTokenEntity> entities) {
        }

        @Override
        public void deleteAll() {
            byId.clear();
        }
    }
}
