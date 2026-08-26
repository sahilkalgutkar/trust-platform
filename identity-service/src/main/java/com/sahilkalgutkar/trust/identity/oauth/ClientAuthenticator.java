package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.repo.OAuthClientRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Authenticates the client at the token endpoint.
 *
 * <p>Supports both {@code client_secret_basic} and {@code client_secret_post}. The lookup runs
 * inside the tenant bound by the request path, so client ids only have to be unique per tenant, and
 * presenting tenant A's client credentials on tenant B's token endpoint fails at "no such client"
 * rather than at some later check.
 */
@Component
public class ClientAuthenticator {

    private final OAuthClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientAuthenticator(OAuthClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public OAuthClientEntity authenticate(String authorizationHeader, String clientIdParam,
                                          String clientSecretParam) {
        Credentials credentials = parseBasic(authorizationHeader)
                .orElseGet(() -> new Credentials(clientIdParam, clientSecretParam));

        if (credentials.clientId() == null || credentials.clientId().isBlank()) {
            throw OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT, "Client authentication failed");
        }

        OAuthClientEntity client = clientRepository.findByClientId(credentials.clientId())
                .orElseThrow(() -> OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT,
                        "Client authentication failed"));

        boolean secretPresented = credentials.clientSecret() != null && !credentials.clientSecret().isBlank();
        if (client.isPublicClient()) {
            // A public client has no secret to present. If one arrives anyway, something is
            // misconfigured or someone is guessing; either way it is not an authenticated client.
            if (secretPresented) {
                throw OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT, "Client authentication failed");
            }
            return client;
        }
        if (!secretPresented
                || !passwordEncoder.matches(credentials.clientSecret(), client.getClientSecretHash())) {
            throw OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT, "Client authentication failed");
        }
        return client;
    }

    static Optional<Credentials> parseBasic(String header) {
        if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
            return Optional.empty();
        }
        try {
            String decoded = new String(Base64.getDecoder().decode(header.substring(6).trim()),
                    StandardCharsets.UTF_8);
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                return Optional.empty();
            }
            return Optional.of(new Credentials(
                    java.net.URLDecoder.decode(decoded.substring(0, separator), StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(decoded.substring(separator + 1), StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException malformedBase64) {
            return Optional.empty();
        }
    }

    record Credentials(String clientId, String clientSecret) {
    }
}
