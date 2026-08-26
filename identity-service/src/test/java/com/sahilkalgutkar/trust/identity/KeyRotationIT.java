package com.sahilkalgutkar.trust.identity;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Rotation, verified from the angle that actually matters: whether it breaks anyone.
 *
 * <p>Generating a new key is easy. The part worth testing is that the tokens already in the wild
 * keep working until they expire on their own — a provider that invalidates live sessions every
 * time it rotates is a provider whose operators quietly stop rotating.
 */
class KeyRotationIT extends AbstractIdentityIT {

    @Test
    void aTokenIssuedBeforeRotationStillWorksAfterIt() throws Exception {
        Fixture fixture = provision("rot-live", true);
        String tokenBefore = (String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("access_token");
        String kidBefore = SignedJWT.parse(tokenBefore).getHeader().getKeyID();

        rotate(fixture);

        HttpHeaders bearer = new HttpHeaders();
        bearer.setBearerAuth(tokenBefore);
        ResponseEntity<Map> userInfo = rest.exchange(fixture.issuerPath() + "/userinfo",
                HttpMethod.GET, new HttpEntity<>(bearer), Map.class);

        assertThat(userInfo.getStatusCode().value()).isEqualTo(200);
        assertThat(rest.getForObject(fixture.issuerPath() + "/oauth2/jwks", String.class))
                .contains(kidBefore);
    }

    @Test
    void tokensIssuedAfterRotationUseTheNewKey() throws Exception {
        Fixture fixture = provision("rot-new", true);
        String kidBefore = SignedJWT.parse((String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("access_token")).getHeader().getKeyID();

        String rotatedKid = (String) rotate(fixture).getBody().get("kid");

        String kidAfter = SignedJWT.parse((String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("access_token")).getHeader().getKeyID();

        assertThat(kidAfter).isEqualTo(rotatedKid).isNotEqualTo(kidBefore);
    }

    @Test
    void jwksPublishesBothKeysDuringTheGracePeriod() throws Exception {
        Fixture fixture = provision("rot-jwks", true);
        String kidBefore = SignedJWT.parse((String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("access_token")).getHeader().getKeyID();

        String kidAfter = (String) rotate(fixture).getBody().get("kid");

        String jwks = rest.getForObject(fixture.issuerPath() + "/oauth2/jwks", String.class);
        assertThat(jwks).contains(kidBefore).contains(kidAfter);
        assertThat(jwks).doesNotContain("\"d\":");
    }

    @Test
    void aRefreshIssuedBeforeRotationStillWorksAfterIt() {
        Fixture fixture = provision("rot-refresh", true);
        String refreshToken = (String) exchangeCode(fixture, authorizeForCode(fixture))
                .getBody().get("refresh_token");

        rotate(fixture);

        assertThat(refresh(fixture, refreshToken).getStatusCode().value()).isEqualTo(200);
    }

    @Test
    void rotationRequiresTheAdminKey() {
        Fixture fixture = provision("rot-admin", true);
        HttpHeaders wrongKey = new HttpHeaders();
        wrongKey.set("X-Admin-Key", "not-the-key");

        ResponseEntity<String> response = rest.exchange(fixture.issuerPath() + "/admin/keys/rotate",
                HttpMethod.POST, new HttpEntity<>(wrongKey), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Map<String, Object>> rotate(Fixture fixture) {
        return (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) rest.exchange(
                fixture.issuerPath() + "/admin/keys/rotate", HttpMethod.POST,
                new HttpEntity<>(adminHeaders()), Map.class);
    }
}
