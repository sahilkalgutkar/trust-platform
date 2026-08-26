package com.sahilkalgutkar.trust.identity;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The tenant boundary, attacked from every direction the protocol allows.
 *
 * <p>Both tenants deliberately register the <em>same</em> client id and the <em>same</em> user
 * email, because that is the case where a missing tenant predicate stops being a theoretical bug
 * and starts returning the wrong row. If any query in this service leaked across tenants, one of
 * the tests below would pass where it expects a rejection.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TenantIsolationIT extends AbstractIdentityIT {

    private static final String SHARED_CLIENT_ID = "web-app";
    private static final String SHARED_EMAIL = "ada@shared.test";

    private Fixture alpha;
    private Fixture beta;

    @BeforeAll
    void provisionBothTenants() {
        alpha = provision("iso-alpha", true, SHARED_EMAIL, SHARED_CLIENT_ID,
                "authorization_code,refresh_token");
        beta = provision("iso-beta", true, SHARED_EMAIL, SHARED_CLIENT_ID,
                "authorization_code,refresh_token");
    }

    @Test
    void twoTenantsCanRegisterTheSameClientIdAndTheSameUserEmail() {
        assertThat(alpha.clientId()).isEqualTo(beta.clientId());
        assertThat(alpha.email()).isEqualTo(beta.email());
        assertThat(alpha.clientSecret()).isNotEqualTo(beta.clientSecret());
    }

    @Test
    void eachTenantHasItsOwnIssuer() throws Exception {
        SignedJWT alphaToken = SignedJWT.parse((String) exchangeCode(alpha, authorizeForCode(alpha))
                .getBody().get("access_token"));
        SignedJWT betaToken = SignedJWT.parse((String) exchangeCode(beta, authorizeForCode(beta))
                .getBody().get("access_token"));

        assertThat(alphaToken.getJWTClaimsSet().getIssuer()).endsWith("/t/iso-alpha");
        assertThat(betaToken.getJWTClaimsSet().getIssuer()).endsWith("/t/iso-beta");
        assertThat(alphaToken.getJWTClaimsSet().getClaim("tid"))
                .isNotEqualTo(betaToken.getJWTClaimsSet().getClaim("tid"));
    }

    /** Per-tenant signing keys: a token from one tenant is not verifiable under the other's JWKS. */
    @Test
    void neitherTenantPublishesTheOthersSigningKey() throws Exception {
        String alphaKid = SignedJWT.parse((String) exchangeCode(alpha, authorizeForCode(alpha))
                .getBody().get("access_token")).getHeader().getKeyID();
        exchangeCode(beta, authorizeForCode(beta));

        String betaJwks = rest.getForObject(beta.issuerPath() + "/oauth2/jwks", String.class);
        String alphaJwks = rest.getForObject(alpha.issuerPath() + "/oauth2/jwks", String.class);

        assertThat(alphaJwks).contains(alphaKid);
        assertThat(betaJwks).doesNotContain(alphaKid);
    }

    @Test
    void theSameEmailInBothTenantsIsTwoDifferentPeople() {
        String alphaSubject = (String) userInfo(alpha, accessTokenFor(alpha)).getBody().get("sub");
        String betaSubject = (String) userInfo(beta, accessTokenFor(beta)).getBody().get("sub");

        assertThat(alphaSubject).isNotEqualTo(betaSubject);
    }

    // ------------------------------------------------------------------ cross-tenant attacks

    @Test
    void anAccessTokenFromOneTenantIsRejectedByTheOthersUserInfo() {
        String alphaToken = accessTokenFor(alpha);

        assertThat(userInfo(alpha, alphaToken).getStatusCode().value()).isEqualTo(200);
        assertThat(userInfoRaw(beta, alphaToken).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void anAuthorizationCodeFromOneTenantCannotBeRedeemedAtTheOthersTokenEndpoint() {
        String alphaCode = authorizeForCode(alpha);

        ResponseEntity<Map<String, Object>> response = postForm(beta.issuerPath() + "/oauth2/token",
                basicAuth(beta.clientId(), beta.clientSecret()), Map.of(
                        "grant_type", "authorization_code",
                        "code", alphaCode,
                        "redirect_uri", alpha.redirectUri(),
                        "code_verifier", VERIFIER));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).containsEntry("error", "invalid_grant");

        // And it is still usable in its own tenant, so the rejection was isolation, not consumption.
        assertThat(exchangeCode(alpha, alphaCode).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void aRefreshTokenFromOneTenantIsUnknownToTheOther() {
        String alphaRefresh = (String) exchangeCode(alpha, authorizeForCode(alpha))
                .getBody().get("refresh_token");

        ResponseEntity<Map<String, Object>> response = postForm(beta.issuerPath() + "/oauth2/token",
                basicAuth(beta.clientId(), beta.clientSecret()), Map.of(
                        "grant_type", "refresh_token",
                        "refresh_token", alphaRefresh));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).containsEntry("error", "invalid_grant");
    }

    /** Same client id, different secret: the credentials do not carry across the boundary. */
    @Test
    void oneTenantsClientSecretDoesNotAuthenticateAtTheOther() {
        ResponseEntity<Map<String, Object>> response = postForm(beta.issuerPath() + "/oauth2/token",
                basicAuth(alpha.clientId(), alpha.clientSecret()), Map.of(
                        "grant_type", "refresh_token",
                        "refresh_token", "irrelevant"));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).containsEntry("error", "invalid_client");
    }

    @Test
    void oneTenantsUserCannotLogInAtTheOthersAuthorizationEndpoint() {
        ResponseEntity<String> response = rest.exchange(beta.issuerPath() + "/oauth2/authorize",
                HttpMethod.POST, new HttpEntity<>(form(Map.of(
                        "response_type", "code",
                        "client_id", beta.clientId(),
                        "redirect_uri", beta.redirectUri(),
                        "scope", "openid",
                        "code_challenge", CHALLENGE,
                        "code_challenge_method", "S256",
                        "username", alpha.email(),
                        // Alpha and beta share an email but the accounts are distinct rows; this
                        // password belongs to neither, standing in for a credential-stuffing attempt.
                        "password", "alpha-only-password")), formHeaders()), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void introspectingAnotherTenantsTokenReportsItInactiveRatherThanLeakingItsClaims() {
        String alphaToken = accessTokenFor(alpha);

        ResponseEntity<Map<String, Object>> response = postForm(beta.issuerPath() + "/oauth2/introspect",
                basicAuth(beta.clientId(), beta.clientSecret()), Map.of("token", alphaToken));

        assertThat(response.getBody()).containsEntry("active", false);
        assertThat(response.getBody()).doesNotContainKeys("sub", "scope", "client_id");
    }

    @Test
    void aRedirectUriRegisteredByOneTenantIsNotRegisteredForTheOther() {
        ResponseEntity<String> response = rest.getForEntity(beta.issuerPath()
                        + "/oauth2/authorize?response_type=code&client_id={c}&redirect_uri={r}"
                        + "&scope=openid&code_challenge={cc}&code_challenge_method=S256",
                String.class, beta.clientId(), alpha.redirectUri(), CHALLENGE);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void anAdminCallScopedToOneTenantDoesNotTouchTheOther() {
        // The same email again: it must be creatable in beta because alpha's row is invisible here.
        ResponseEntity<String> response = rest.exchange(beta.issuerPath() + "/admin/users",
                HttpMethod.POST, new HttpEntity<>(Map.of(
                        "email", "second@shared.test", "password", "another good passphrase"),
                        adminHeaders()), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(201);
    }

    // ------------------------------------------------------------------ helpers

    private String accessTokenFor(Fixture fixture) {
        return (String) exchangeCode(fixture, authorizeForCode(fixture)).getBody().get("access_token");
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> userInfo(Fixture fixture, String accessToken) {
        return (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) userInfoRaw(fixture, accessToken);
    }

    private ResponseEntity<?> userInfoRaw(Fixture fixture, String accessToken) {
        HttpHeaders bearer = new HttpHeaders();
        bearer.setBearerAuth(accessToken);
        return rest.exchange(fixture.issuerPath() + "/userinfo", HttpMethod.GET,
                new HttpEntity<>(bearer), Map.class);
    }
}
