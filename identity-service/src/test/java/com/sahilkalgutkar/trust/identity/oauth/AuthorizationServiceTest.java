package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.Tokens;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import com.sahilkalgutkar.trust.identity.audit.AuditRecorder;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.AuthorizationCodeEntity;
import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.repo.AuthorizationCodeRepository;
import com.sahilkalgutkar.trust.identity.repo.OAuthClientRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationServiceTest {

    private static final String TENANT = "11111111-1111-1111-1111-111111111111";
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final String REDIRECT = "https://app.acme.test/callback";
    private static final String CHALLENGE = PkceValidator.sha256Base64Url(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

    private final OAuthClientRepository clientRepository = mock(OAuthClientRepository.class);
    private final AuthorizationCodeRepository codeRepository = mock(AuthorizationCodeRepository.class);
    private final UserAuthenticator userAuthenticator = mock(UserAuthenticator.class);
    private final AuditRecorder auditRecorder = mock(AuditRecorder.class);
    private final IdentityProperties properties = new IdentityProperties();

    private AuthorizationService service;
    private OAuthClientEntity client;
    private UserEntity user;

    @BeforeEach
    void setUp() {
        TenantContext.set(TENANT);
        service = new AuthorizationService(clientRepository, codeRepository, userAuthenticator,
                new PkceValidator(), auditRecorder, properties, Clock.fixed(NOW, ZoneOffset.UTC));

        client = new OAuthClientEntity(UUID.randomUUID(), "web-app", "Web App");
        client.setRedirectUris(REDIRECT + ",https://app.acme.test/other");
        client.setGrantTypes("authorization_code,refresh_token");
        client.setScopes("openid,profile");

        user = new UserEntity(UUID.randomUUID(), "ada@acme.test", "hash");

        when(clientRepository.findByClientId(anyString())).thenReturn(Optional.empty());
        when(clientRepository.findByClientId("web-app")).thenReturn(Optional.of(client));
        when(userAuthenticator.authenticate(anyString(), anyString())).thenReturn(Optional.empty());
        when(userAuthenticator.authenticate("ada@acme.test", "hunter2")).thenReturn(Optional.of(user));
    }

    @AfterEach
    void clearTenant() {
        TenantContext.clear();
    }

    @Test
    void aWellFormedRequestValidatesIntoAChallenge() {
        AuthorizationChallenge challenge = service.validate(request(REDIRECT, "openid"));

        assertThat(challenge.clientId()).isEqualTo("web-app");
        assertThat(challenge.clientName()).isEqualTo("Web App");
        assertThat(challenge.redirectUri()).isEqualTo(REDIRECT);
        assertThat(challenge.scope()).isEqualTo("openid");
        assertThat(challenge.state()).isEqualTo("xyz");
        assertThat(challenge.pkceRequired()).isTrue();
    }

    @Test
    void anOmittedScopeDefaultsToEverythingTheClientRegistered() {
        assertThat(service.validate(request(REDIRECT, null)).scope()).isEqualTo("openid profile");
    }

    // ------------------------------------------------- errors that must NOT redirect

    /**
     * Redirecting to report that a redirect URI is untrusted would <em>be</em> the open redirect.
     * These two cases stay on this server.
     */
    @Test
    void anUnknownClientIsReportedWithoutRedirecting() {
        assertThatThrownBy(() -> service.validate(new AuthorizeRequest("code", "ghost", REDIRECT,
                "openid", "xyz", null, CHALLENGE, "S256")))
                .isInstanceOf(OAuthException.class)
                .isNotInstanceOf(RedirectableOAuthException.class)
                .hasMessageContaining("Unknown client");
    }

    @Test
    void anUnregisteredRedirectUriIsReportedWithoutRedirecting() {
        assertThatThrownBy(() -> service.validate(request("https://evil.test/steal", "openid")))
                .isInstanceOf(OAuthException.class)
                .isNotInstanceOf(RedirectableOAuthException.class)
                .hasMessageContaining("does not exactly match");
    }

    @Test
    void aRedirectUriThatOnlyPrefixMatchesIsRejected() {
        assertThatThrownBy(() -> service.validate(request(REDIRECT + ".evil.test", "openid")))
                .isInstanceOf(OAuthException.class)
                .isNotInstanceOf(RedirectableOAuthException.class);
    }

    @Test
    void aMissingClientIdIsReportedWithoutRedirecting() {
        assertThatThrownBy(() -> service.validate(new AuthorizeRequest("code", null, REDIRECT,
                "openid", "xyz", null, CHALLENGE, "S256")))
                .isInstanceOf(OAuthException.class)
                .isNotInstanceOf(RedirectableOAuthException.class);
    }

    // ------------------------------------------------- errors that must redirect

    @Test
    void anUnsupportedResponseTypeRedirectsWithTheErrorAndState() {
        assertThatThrownBy(() -> service.validate(new AuthorizeRequest("token", "web-app", REDIRECT,
                "openid", "xyz", null, CHALLENGE, "S256")))
                .isInstanceOf(RedirectableOAuthException.class)
                .satisfies(e -> {
                    RedirectableOAuthException redirectable = (RedirectableOAuthException) e;
                    assertThat(redirectable.getError()).isEqualTo("unsupported_response_type");
                    assertThat(redirectable.getRedirectUri()).isEqualTo(REDIRECT);
                    assertThat(redirectable.getState()).isEqualTo("xyz");
                });
    }

    @Test
    void aClientNotRegisteredForTheCodeGrantRedirects() {
        client.setGrantTypes("client_credentials");

        assertThatThrownBy(() -> service.validate(request(REDIRECT, "openid")))
                .isInstanceOf(RedirectableOAuthException.class);
    }

    @Test
    void aMissingPkceChallengeRedirectsWhenTheClientRequiresPkce() {
        assertThatThrownBy(() -> service.validate(new AuthorizeRequest("code", "web-app", REDIRECT,
                "openid", "xyz", null, null, null)))
                .isInstanceOf(RedirectableOAuthException.class)
                .hasMessageContaining("code_challenge is required");
    }

    @Test
    void aScopeBeyondTheClientsRegistrationRedirects() {
        assertThatThrownBy(() -> service.validate(request(REDIRECT, "openid admin")))
                .isInstanceOf(RedirectableOAuthException.class)
                .hasMessageContaining("exceeds what this client is registered for");
    }

    @Test
    void aClientWithPkceDisabledMayOmitTheChallenge() {
        client.setRequirePkce(false);

        AuthorizationChallenge challenge = service.validate(new AuthorizeRequest("code", "web-app",
                REDIRECT, "openid", "xyz", null, null, null));

        assertThat(challenge.pkceRequired()).isFalse();
    }

    // ------------------------------------------------- issuing the code

    @Test
    void successfulAuthenticationIssuesACodeStoredOnlyAsAHash() {
        Optional<IssuedCode> issued = service.authorize(request(REDIRECT, "openid"), "ada@acme.test", "hunter2");

        assertThat(issued).isPresent();
        AuthorizationCodeEntity stored = capturedCode();
        assertThat(stored.getCodeHash()).isEqualTo(Tokens.hash(issued.get().code()));
        assertThat(stored.getCodeHash()).isNotEqualTo(issued.get().code());
        assertThat(stored.getUserId()).isEqualTo(user.getId());
        assertThat(stored.getClientId()).isEqualTo("web-app");
        assertThat(stored.getRedirectUri()).isEqualTo(REDIRECT);
        assertThat(stored.getExpiresAt()).isEqualTo(NOW.plus(properties.getAuthorizationCodeTtl()));
    }

    @Test
    void theNonceAndPkceCommitmentAreCapturedWithTheCode() {
        service.authorize(new AuthorizeRequest("code", "web-app", REDIRECT, "openid", "xyz",
                "n-0S6_WzA2Mj", CHALLENGE, "S256"), "ada@acme.test", "hunter2");

        AuthorizationCodeEntity stored = capturedCode();
        assertThat(stored.getNonce()).isEqualTo("n-0S6_WzA2Mj");
        assertThat(stored.getCodeChallenge()).isEqualTo(CHALLENGE);
        assertThat(stored.getCodeChallengeMethod()).isEqualTo("S256");
    }

    /** An absent method means S256, not "no PKCE" — RFC 7636 §4.3 makes S256 the default. */
    @Test
    void anAbsentChallengeMethodIsRecordedAsS256() {
        service.authorize(new AuthorizeRequest("code", "web-app", REDIRECT, "openid", "xyz",
                null, CHALLENGE, null), "ada@acme.test", "hunter2");

        assertThat(capturedCode().getCodeChallengeMethod()).isEqualTo("S256");
    }

    @Test
    void aFlowWithoutPkceRecordsNoMethod() {
        client.setRequirePkce(false);

        service.authorize(new AuthorizeRequest("code", "web-app", REDIRECT, "openid", "xyz",
                null, null, null), "ada@acme.test", "hunter2");

        assertThat(capturedCode().getCodeChallengeMethod()).isNull();
    }

    @Test
    void theStateIsHandedBackForTheClientToMatch() {
        Optional<IssuedCode> issued = service.authorize(request(REDIRECT, "openid"), "ada@acme.test", "hunter2");

        assertThat(issued.orElseThrow().state()).isEqualTo("xyz");
        assertThat(issued.orElseThrow().redirectUri()).isEqualTo(REDIRECT);
    }

    @Test
    void aFailedLoginIssuesNoCodeAndIsAudited() {
        Optional<IssuedCode> issued = service.authorize(request(REDIRECT, "openid"), "ada@acme.test", "wrong");

        assertThat(issued).isEmpty();
        verify(codeRepository, never()).save(any());

        ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditRecorder).record(event.capture());
        assertThat(event.getValue().action()).isEqualTo("authorization.login_failed");
        assertThat(event.getValue().outcome().name()).isEqualTo("DENIED");
    }

    @Test
    void aSuccessfulAuthorizationIsAudited() {
        service.authorize(request(REDIRECT, "openid"), "ada@acme.test", "hunter2");

        ArgumentCaptor<AuditEvent> event = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditRecorder).record(event.capture());
        assertThat(event.getValue().action()).isEqualTo("authorization.code_issued");
        assertThat(event.getValue().actor()).isEqualTo("user:" + user.getId());
    }

    @Test
    void anInvalidRequestIsRejectedBeforeAnyCredentialIsChecked() {
        assertThatThrownBy(() -> service.authorize(request("https://evil.test/steal", "openid"),
                "ada@acme.test", "hunter2"))
                .isInstanceOf(OAuthException.class);

        verify(userAuthenticator, never()).authenticate(anyString(), anyString());
    }

    private AuthorizationCodeEntity capturedCode() {
        ArgumentCaptor<AuthorizationCodeEntity> captor =
                ArgumentCaptor.forClass(AuthorizationCodeEntity.class);
        verify(codeRepository).save(captor.capture());
        return captor.getValue();
    }

    private static AuthorizeRequest request(String redirectUri, String scope) {
        return new AuthorizeRequest("code", "web-app", redirectUri, scope, "xyz", null, CHALLENGE, "S256");
    }
}
