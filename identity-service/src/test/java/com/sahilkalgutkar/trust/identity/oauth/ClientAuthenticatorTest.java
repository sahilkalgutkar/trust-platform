package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.identity.domain.OAuthClientEntity;
import com.sahilkalgutkar.trust.identity.repo.OAuthClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientAuthenticatorTest {

    private static final String SECRET = "s3cr3t-value";

    private final OAuthClientRepository repository = mock(OAuthClientRepository.class);
    private final PasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final ClientAuthenticator authenticator = new ClientAuthenticator(repository, encoder);

    private OAuthClientEntity confidential;

    @BeforeEach
    void setUp() {
        confidential = new OAuthClientEntity(UUID.randomUUID(), "web-app", "Web App");
        confidential.setClientSecretHash(encoder.encode(SECRET));
        when(repository.findByClientId(anyString())).thenReturn(Optional.empty());
        when(repository.findByClientId("web-app")).thenReturn(Optional.of(confidential));
    }

    @Test
    void clientSecretBasicAuthenticatesTheClient() {
        assertThat(authenticator.authenticate(basic("web-app", SECRET), null, null))
                .isSameAs(confidential);
    }

    @Test
    void clientSecretPostAuthenticatesTheClient() {
        assertThat(authenticator.authenticate(null, "web-app", SECRET)).isSameAs(confidential);
    }

    @Test
    void theBasicHeaderSchemeIsMatchedCaseInsensitively() {
        String header = "basic " + Base64.getEncoder()
                .encodeToString(("web-app:" + SECRET).getBytes(StandardCharsets.UTF_8));

        assertThat(authenticator.authenticate(header, null, null)).isSameAs(confidential);
    }

    /** RFC 6749 §2.3.1 form-encodes the two halves before base64, so they must be decoded back. */
    @Test
    void percentEncodedCredentialsAreDecodedBeforeComparison() {
        OAuthClientEntity client = new OAuthClientEntity(UUID.randomUUID(), "web app", "Web App");
        client.setClientSecretHash(encoder.encode("p@ss word"));
        when(repository.findByClientId("web app")).thenReturn(Optional.of(client));

        assertThat(authenticator.authenticate(basic("web+app", "p%40ss+word"), null, null))
                .isSameAs(client);
    }

    @Test
    void aWrongSecretIsRejected() {
        assertThatThrownBy(() -> authenticator.authenticate(basic("web-app", "wrong"), null, null))
                .isInstanceOf(OAuthException.class)
                .hasMessage("Client authentication failed");
    }

    @Test
    void anUnknownClientIsRejectedWithTheSameMessageAsAWrongSecret() {
        assertThatThrownBy(() -> authenticator.authenticate(basic("ghost", SECRET), null, null))
                .isInstanceOf(OAuthException.class)
                .hasMessage("Client authentication failed");
    }

    @Test
    void aMissingClientIdIsRejected() {
        assertThatThrownBy(() -> authenticator.authenticate(null, null, null))
                .isInstanceOf(OAuthException.class);
        assertThatThrownBy(() -> authenticator.authenticate(null, "  ", SECRET))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aConfidentialClientPresentingNoSecretIsRejected() {
        assertThatThrownBy(() -> authenticator.authenticate(null, "web-app", null))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aPublicClientAuthenticatesWithNoSecret() {
        OAuthClientEntity spa = new OAuthClientEntity(UUID.randomUUID(), "spa", "SPA");
        when(repository.findByClientId("spa")).thenReturn(Optional.of(spa));

        assertThat(authenticator.authenticate(null, "spa", null)).isSameAs(spa);
    }

    @Test
    void aPublicClientPresentingASecretIsRejectedRatherThanIgnored() {
        OAuthClientEntity spa = new OAuthClientEntity(UUID.randomUUID(), "spa", "SPA");
        when(repository.findByClientId("spa")).thenReturn(Optional.of(spa));

        assertThatThrownBy(() -> authenticator.authenticate(null, "spa", "anything"))
                .isInstanceOf(OAuthException.class);
    }

    @Test
    void aMalformedBasicHeaderFallsBackToTheFormParameters() {
        assertThat(authenticator.authenticate("Basic not-base64!!", "web-app", SECRET))
                .isSameAs(confidential);
    }

    @Test
    void aBasicHeaderWithoutAColonFallsBackToTheFormParameters() {
        String header = "Basic " + Base64.getEncoder()
                .encodeToString("no-separator".getBytes(StandardCharsets.UTF_8));

        assertThat(authenticator.authenticate(header, "web-app", SECRET)).isSameAs(confidential);
    }

    @Test
    void aNonBasicAuthorizationHeaderIsIgnored() {
        assertThat(ClientAuthenticator.parseBasic("Bearer abc")).isEmpty();
        assertThat(ClientAuthenticator.parseBasic(null)).isEmpty();
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }
}
