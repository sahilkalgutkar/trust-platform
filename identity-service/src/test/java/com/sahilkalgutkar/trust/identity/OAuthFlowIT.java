package com.sahilkalgutkar.trust.identity;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** The authorization code flow end to end, against a real database. */
class OAuthFlowIT extends AbstractIdentityIT {

    @Test
    void aClientCanDiscoverEverythingItNeedsFromTheTenantsMetadata() {
        Fixture fixture = provision("flow-discovery", true);

        @SuppressWarnings("unchecked")
        Map<String, Object> document = rest.getForObject(
                fixture.issuerPath() + "/.well-known/openid-configuration", Map.class);

        assertThat(document.get("issuer")).asString().endsWith("/t/flow-discovery");
        assertThat(document.get("token_endpoint")).asString().endsWith("/t/flow-discovery/oauth2/token");
        assertThat(document.get("jwks_uri")).asString().endsWith("/t/flow-discovery/oauth2/jwks");
        assertThat(document.get("code_challenge_methods_supported").toString()).contains("S256");
        assertThat(document.get("grant_types_supported").toString())
                .contains("authorization_code", "refresh_token", "client_credentials");
    }

    @Test
    void theJwksEndpointPublishesPublicKeysAndNeverPrivateOnes() {
        Fixture fixture = provision("flow-jwks", true);
        exchangeCode(fixture, authorizeForCode(fixture));

        String jwks = rest.getForObject(fixture.issuerPath() + "/oauth2/jwks", String.class);

        assertThat(jwks).contains("\"kty\":\"RSA\"").contains("\"n\":").contains("\"e\":");
        assertThat(jwks).doesNotContain("\"d\":").doesNotContain("\"p\":").doesNotContain("\"q\":");
    }

    @Test
    void theAuthorizationEndpointDescribesWhatIsBeingConsentedTo() {
        Fixture fixture = provision("flow-challenge", true);

        @SuppressWarnings("unchecked")
        Map<String, Object> challenge = rest.getForObject(fixture.issuerPath()
                        + "/oauth2/authorize?response_type=code&client_id={c}&redirect_uri={r}"
                        + "&scope=openid&state=xyz&code_challenge={cc}&code_challenge_method=S256",
                Map.class, fixture.clientId(), fixture.redirectUri(), CHALLENGE);

        assertThat(challenge).containsEntry("clientId", fixture.clientId())
                .containsEntry("scope", "openid")
                .containsEntry("state", "xyz")
                .containsEntry("pkceRequired", true);
    }

    @Test
    void aFullAuthorizationCodeExchangeYieldsUsableTokens() throws Exception {
        Fixture fixture = provision("flow-happy", true);

        ResponseEntity<Map<String, Object>> tokens = exchangeCode(fixture, authorizeForCode(fixture));

        assertThat(tokens.getStatusCode().value()).isEqualTo(200);
        assertThat(tokens.getBody()).containsKeys("access_token", "refresh_token", "id_token");
        assertThat(tokens.getBody()).containsEntry("token_type", "Bearer");
        assertThat(tokens.getHeaders().getCacheControl()).contains("no-store");

        SignedJWT accessToken = SignedJWT.parse((String) tokens.getBody().get("access_token"));
        assertThat(accessToken.getJWTClaimsSet().getIssuer()).endsWith("/t/flow-happy");
        assertThat(accessToken.getJWTClaimsSet().getAudience()).containsExactly(fixture.clientId());
        assertThat(accessToken.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    @Test
    void theAccessTokenIsAcceptedByUserInfo() {
        Fixture fixture = provision("flow-userinfo", true);
        String accessToken = (String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("access_token");

        HttpHeaders bearer = new HttpHeaders();
        bearer.setBearerAuth(accessToken);
        @SuppressWarnings("unchecked")
        ResponseEntity<Map> userInfo = rest.exchange(fixture.issuerPath() + "/userinfo",
                HttpMethod.GET, new HttpEntity<>(bearer), Map.class);

        assertThat(userInfo.getStatusCode().value()).isEqualTo(200);
        assertThat(userInfo.getBody()).containsEntry("email", fixture.email());
    }

    @Test
    void userInfoRejectsAMissingOrGarbageToken() {
        Fixture fixture = provision("flow-userinfo-bad", true);

        assertThat(rest.getForEntity(fixture.issuerPath() + "/userinfo", String.class)
                .getStatusCode().value()).isEqualTo(401);

        HttpHeaders bearer = new HttpHeaders();
        bearer.setBearerAuth("not-a-real-token");
        assertThat(rest.exchange(fixture.issuerPath() + "/userinfo", HttpMethod.GET,
                new HttpEntity<>(bearer), String.class).getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void refreshingRotatesTheTokenAndTheOldOneStopsWorking() {
        Fixture fixture = provision("flow-refresh", true);
        String original = (String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("refresh_token");

        ResponseEntity<Map<String, Object>> rotated = refresh(fixture, original);

        assertThat(rotated.getStatusCode().value()).isEqualTo(200);
        assertThat(rotated.getBody().get("refresh_token")).isNotEqualTo(original);

        ResponseEntity<Map<String, Object>> replay = refresh(fixture, original);
        assertThat(replay.getStatusCode().value()).isEqualTo(400);
        assertThat(replay.getBody()).containsEntry("error", "invalid_grant");
    }

    /** Detecting the replay must also invalidate the token the legitimate client is holding. */
    @Test
    void aDetectedReplayKillsTheWholeFamilyIncludingTheRotatedToken() {
        Fixture fixture = provision("flow-reuse", true);
        String stolen = (String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("refresh_token");
        String rotated = (String) refresh(fixture, stolen).getBody().get("refresh_token");

        refresh(fixture, stolen);

        assertThat(refresh(fixture, rotated).getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void anAuthorizationCodeWorksExactlyOnce() {
        Fixture fixture = provision("flow-code-replay", true);
        String code = authorizeForCode(fixture);

        assertThat(exchangeCode(fixture, code).getStatusCode().value()).isEqualTo(200);

        ResponseEntity<Map<String, Object>> second = exchangeCode(fixture, code);
        assertThat(second.getStatusCode().value()).isEqualTo(400);
        assertThat(second.getBody()).containsEntry("error", "invalid_grant");
    }

    @Test
    void theWrongPkceVerifierIsRejectedAtTheTokenEndpoint() {
        Fixture fixture = provision("flow-pkce", true);
        String code = authorizeForCode(fixture);

        ResponseEntity<Map<String, Object>> response = postForm(
                fixture.issuerPath() + "/oauth2/token", clientAuth(fixture), Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "redirect_uri", fixture.redirectUri(),
                        "code_verifier", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                        "client_id", fixture.clientId()));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).containsEntry("error", "invalid_grant");
    }

    @Test
    void aWrongClientSecretIsRejectedWithA401AndAChallenge() {
        Fixture fixture = provision("flow-bad-secret", true);
        String code = authorizeForCode(fixture);

        ResponseEntity<Map<String, Object>> response = postForm(
                fixture.issuerPath() + "/oauth2/token", basicAuth(fixture.clientId(), "wrong"), Map.of(
                        "grant_type", "authorization_code",
                        "code", code,
                        "redirect_uri", fixture.redirectUri(),
                        "code_verifier", VERIFIER));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).startsWith("Basic");
    }

    @Test
    void aFailedLoginIsNotRedirectedBackToTheClient() {
        Fixture fixture = provision("flow-bad-login", true);

        ResponseEntity<String> response = rest.exchange(fixture.issuerPath() + "/oauth2/authorize",
                HttpMethod.POST, new HttpEntity<>(form(Map.of(
                        "response_type", "code",
                        "client_id", fixture.clientId(),
                        "redirect_uri", fixture.redirectUri(),
                        "scope", "openid",
                        "code_challenge", CHALLENGE,
                        "code_challenge_method", "S256",
                        "username", fixture.email(),
                        "password", "wrong password")), formHeaders()), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getLocation()).isNull();
    }

    /** An unregistered redirect URI must not be redirected to, even to report the error. */
    @Test
    void anUnregisteredRedirectUriIsRefusedWithoutARedirect() {
        Fixture fixture = provision("flow-open-redirect", true);

        ResponseEntity<String> response = rest.getForEntity(fixture.issuerPath()
                        + "/oauth2/authorize?response_type=code&client_id={c}&redirect_uri={r}"
                        + "&scope=openid&code_challenge={cc}&code_challenge_method=S256",
                String.class, fixture.clientId(), "https://evil.test/steal", CHALLENGE);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getHeaders().getLocation()).isNull();
        assertThat(response.getBody()).contains("redirect_uri does not exactly match");
    }

    @Test
    void aScopeBeyondTheRegistrationRedirectsTheErrorBackToTheClient() {
        Fixture fixture = provision("flow-scope", true);

        ResponseEntity<String> response = rest.getForEntity(fixture.issuerPath()
                        + "/oauth2/authorize?response_type=code&client_id={c}&redirect_uri={r}"
                        + "&scope=openid%20admin&state=xyz&code_challenge={cc}&code_challenge_method=S256",
                String.class, fixture.clientId(), fixture.redirectUri(), CHALLENGE);

        assertThat(response.getStatusCode().value()).isEqualTo(302);
        assertThat(response.getHeaders().getLocation().toString())
                .startsWith(fixture.redirectUri())
                .contains("error=invalid_scope")
                .contains("state=xyz");
    }

    @Test
    void aPublicClientCompletesTheFlowWithPkceAndNoSecret() {
        Fixture fixture = provision("flow-public", false);

        ResponseEntity<Map<String, Object>> tokens = exchangeCode(fixture, authorizeForCode(fixture));

        assertThat(tokens.getStatusCode().value()).isEqualTo(200);
        assertThat(tokens.getBody()).containsKey("access_token");
    }

    @Test
    void aConfidentialClientCanUseTheClientCredentialsGrant() {
        Fixture fixture = provision("flow-cc", true, "svc@acme.test", "batch-job", "client_credentials");

        ResponseEntity<Map<String, Object>> tokens = postForm(fixture.issuerPath() + "/oauth2/token",
                basicAuth(fixture.clientId(), fixture.clientSecret()),
                Map.of("grant_type", "client_credentials", "scope", "profile"));

        assertThat(tokens.getStatusCode().value()).isEqualTo(200);
        assertThat(tokens.getBody()).containsKey("access_token").doesNotContainKey("refresh_token");
    }

    @Test
    void introspectionReportsALiveTokenAndARevokedOne() {
        Fixture fixture = provision("flow-introspect", true);
        Map<String, Object> tokens = exchangeCode(fixture, authorizeForCode(fixture)).getBody();

        ResponseEntity<Map<String, Object>> live = postForm(fixture.issuerPath() + "/oauth2/introspect",
                basicAuth(fixture.clientId(), fixture.clientSecret()),
                Map.of("token", (String) tokens.get("access_token")));
        assertThat(live.getBody()).containsEntry("active", true)
                .containsEntry("client_id", fixture.clientId());

        rest.exchange(fixture.issuerPath() + "/oauth2/revoke", HttpMethod.POST,
                new HttpEntity<>(form(Map.of("token", (String) tokens.get("refresh_token"))),
                        basicAuth(fixture.clientId(), fixture.clientSecret())), Void.class);

        ResponseEntity<Map<String, Object>> revoked = postForm(fixture.issuerPath() + "/oauth2/introspect",
                basicAuth(fixture.clientId(), fixture.clientSecret()),
                Map.of("token", (String) tokens.get("refresh_token")));
        assertThat(revoked.getBody()).containsEntry("active", false);
    }

    @Test
    void introspectingAGarbageTokenIsInactiveRatherThanAnError() {
        Fixture fixture = provision("flow-introspect-junk", true);

        ResponseEntity<Map<String, Object>> response = postForm(
                fixture.issuerPath() + "/oauth2/introspect",
                basicAuth(fixture.clientId(), fixture.clientSecret()), Map.of("token", "nonsense"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsEntry("active", false);
    }

    @Test
    void requestsForAnUnknownTenantAreRejectedBeforeAnythingElseRuns() {
        assertThat(rest.getForEntity("/t/no-such-tenant/oauth2/jwks", String.class)
                .getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void theAdminEndpointsRefuseAWrongKey() {
        HttpHeaders wrongKey = new HttpHeaders();
        wrongKey.setContentType(org.springframework.http.MediaType.APPLICATION_JSON);
        wrongKey.set("X-Admin-Key", "not-the-key");

        ResponseEntity<String> response = rest.exchange("/admin/tenants", HttpMethod.POST,
                new HttpEntity<>(Map.of("slug", "should-not-exist", "name", "Nope"), wrongKey),
                String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }
}
