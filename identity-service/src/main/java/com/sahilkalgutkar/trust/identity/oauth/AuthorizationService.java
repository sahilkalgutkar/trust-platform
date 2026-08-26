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
import com.sahilkalgutkar.trust.identity.domain.UserEntity;
import com.sahilkalgutkar.trust.identity.repo.AuthorizationCodeRepository;
import com.sahilkalgutkar.trust.identity.repo.OAuthClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

/**
 * The authorization endpoint: validates the request, authenticates the user, and mints a code.
 *
 * <p>The ordering in {@link #validate} is the whole security story of this class. Client identity
 * and redirect URI are established <em>first</em>, because until they are, there is no address this
 * server has any business redirecting to. Only afterwards do the failures become redirectable.
 */
@Service
public class AuthorizationService {

    private final OAuthClientRepository clientRepository;
    private final AuthorizationCodeRepository codeRepository;
    private final UserAuthenticator userAuthenticator;
    private final PkceValidator pkceValidator;
    private final AuditRecorder auditRecorder;
    private final IdentityProperties properties;
    private final Clock clock;

    public AuthorizationService(OAuthClientRepository clientRepository,
                                AuthorizationCodeRepository codeRepository,
                                UserAuthenticator userAuthenticator,
                                PkceValidator pkceValidator,
                                AuditRecorder auditRecorder,
                                IdentityProperties properties,
                                Clock clock) {
        this.clientRepository = clientRepository;
        this.codeRepository = codeRepository;
        this.userAuthenticator = userAuthenticator;
        this.pkceValidator = pkceValidator;
        this.auditRecorder = auditRecorder;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public AuthorizationChallenge validate(AuthorizeRequest request) {
        OAuthClientEntity client = requireClientAndRedirectUri(request);

        if (!"code".equals(request.responseType())) {
            throw new RedirectableOAuthException("unsupported_response_type",
                    "Only the authorization code flow is supported",
                    request.redirectUri(), request.state());
        }
        if (!client.allowsGrantType("authorization_code")) {
            throw new RedirectableOAuthException(OAuthErrors.UNAUTHORIZED_CLIENT,
                    "This client is not registered for the authorization code grant",
                    request.redirectUri(), request.state());
        }
        // Past this point the client and its redirect URI are proven, so failures are reported to
        // the client by redirect rather than rendered to the user.
        String scope = redirectingErrors(request, () -> {
            if (client.isRequirePkce()) {
                pkceValidator.validateChallenge(request.codeChallenge(), request.codeChallengeMethod());
            }
            return Scopes.resolveRequested(request.scope(), client.allowedScopes());
        });

        return new AuthorizationChallenge(client.getClientId(), client.getName(),
                request.redirectUri(), scope, request.state(), client.isRequirePkce());
    }

    /**
     * Validates, authenticates the user, and issues a code. Returns empty when the credentials are
     * wrong — that is not a protocol error to hand back to the client, it is a failed login the
     * user should be asked to retry.
     */
    @Transactional
    public Optional<IssuedCode> authorize(AuthorizeRequest request, String username, String password) {
        AuthorizationChallenge challenge = validate(request);

        Optional<UserEntity> user = userAuthenticator.authenticate(username, password);
        if (user.isEmpty()) {
            auditRecorder.record(AuditEvent.builder(TenantContext.require(), "authorization.login_failed")
                    .actor("user:" + (username == null ? "unknown" : username))
                    .outcome(AuditOutcome.DENIED)
                    .resource("client", request.clientId())
                    .occurredAt(clock.instant())
                    .build());
            return Optional.empty();
        }

        String rawCode = Tokens.generate();
        AuthorizationCodeEntity entity = new AuthorizationCodeEntity(
                UUID.randomUUID(),
                Tokens.hash(rawCode),
                challenge.clientId(),
                user.get().getId(),
                challenge.redirectUri(),
                challenge.scope(),
                clock.instant().plus(properties.getAuthorizationCodeTtl()));
        entity.setNonce(request.nonce());
        entity.setCodeChallenge(request.codeChallenge());
        // The method is stored alongside the challenge and read back from here at token time, so a
        // token request cannot downgrade an S256 challenge to plain by claiming it was plain.
        entity.setCodeChallengeMethod(request.codeChallenge() == null
                ? null
                : Optional.ofNullable(request.codeChallengeMethod()).orElse(PkceValidator.METHOD_S256));
        codeRepository.save(entity);

        auditRecorder.record(AuditEvent.builder(TenantContext.require(), "authorization.code_issued")
                .actor("user:" + user.get().getId())
                .resource("client", challenge.clientId())
                .attribute("scope", challenge.scope())
                .attribute("pkce", entity.getCodeChallengeMethod())
                .occurredAt(clock.instant())
                .build());

        return Optional.of(new IssuedCode(rawCode, challenge.redirectUri(), request.state()));
    }

    private OAuthClientEntity requireClientAndRedirectUri(AuthorizeRequest request) {
        if (request.clientId() == null || request.clientId().isBlank()) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST, "client_id is required");
        }
        OAuthClientEntity client = clientRepository.findByClientId(request.clientId())
                .orElseThrow(() -> OAuthException.badRequest(OAuthErrors.INVALID_CLIENT, "Unknown client"));
        if (!client.allowsRedirectUri(request.redirectUri())) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_REQUEST,
                    "redirect_uri does not exactly match a registered URI");
        }
        return client;
    }

    private static String redirectingErrors(AuthorizeRequest request,
                                            java.util.function.Supplier<String> body) {
        try {
            return body.get();
        } catch (RedirectableOAuthException alreadyRedirectable) {
            throw alreadyRedirectable;
        } catch (OAuthException e) {
            throw new RedirectableOAuthException(e.getError(), e.getMessage(),
                    request.redirectUri(), request.state());
        }
    }
}
