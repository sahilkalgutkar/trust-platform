package com.sahilkalgutkar.trust.identity.web;

import com.sahilkalgutkar.trust.common.error.ApiError;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.common.tenant.MissingTenantException;
import com.sahilkalgutkar.trust.identity.oauth.OAuthException;
import com.sahilkalgutkar.trust.identity.oauth.RedirectableOAuthException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthExceptionHandlerTest {

    private final OAuthExceptionHandler handler = new OAuthExceptionHandler();

    @Test
    void aRedirectableErrorBecomesA302CarryingTheErrorAndState() {
        ResponseEntity<Void> response = handler.handleRedirectable(new RedirectableOAuthException(
                OAuthErrors.INVALID_SCOPE, "too broad", "https://app.acme.test/callback", "xyz"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(response.getHeaders().getLocation()).hasToString(
                "https://app.acme.test/callback?error=invalid_scope&state=xyz");
    }

    @Test
    void theStateIsOmittedWhenTheClientSentNone() {
        ResponseEntity<Void> response = handler.handleRedirectable(new RedirectableOAuthException(
                OAuthErrors.INVALID_SCOPE, "too broad", "https://app.acme.test/callback", null));

        assertThat(response.getHeaders().getLocation())
                .hasToString("https://app.acme.test/callback?error=invalid_scope");
    }

    @Test
    void aRedirectUriThatAlreadyHasAQueryStringGetsTheErrorAppended() {
        ResponseEntity<Void> response = handler.handleRedirectable(new RedirectableOAuthException(
                OAuthErrors.ACCESS_DENIED, "denied", "https://app.acme.test/callback?app=1", "xyz"));

        assertThat(response.getHeaders().getLocation()).hasToString(
                "https://app.acme.test/callback?app=1&error=access_denied&state=xyz");
    }

    @Test
    void aProtocolErrorBecomesTheRfcErrorBody() {
        ResponseEntity<ApiError> response = handler.handleOAuth(
                OAuthException.badRequest(OAuthErrors.INVALID_GRANT, "Grant rejected"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo(ApiError.of("invalid_grant", "Grant rejected"));
        assertThat(response.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    /** RFC 6749 §5.2: a 401 has to tell the client how to authenticate. */
    @Test
    void aClientAuthenticationFailureCarriesTheWwwAuthenticateChallenge() {
        ResponseEntity<ApiError> response = handler.handleOAuth(
                OAuthException.unauthorized(OAuthErrors.INVALID_CLIENT, "Client authentication failed"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Basic realm=\"trust-platform\"");
    }

    @Test
    void anUnboundTenantIsAServerErrorRatherThanAnEmptyResult() {
        ResponseEntity<ApiError> response = handler.handleMissingTenant(new MissingTenantException());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().error()).isEqualTo(OAuthErrors.SERVER_ERROR);
    }
}
