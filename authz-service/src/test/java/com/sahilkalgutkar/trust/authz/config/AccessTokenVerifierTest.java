package com.sahilkalgutkar.trust.authz.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Access token verification, from the resource-server side.
 *
 * <p>The cross-tenant cases are the ones that matter: this service takes the tenant from the token's
 * {@code tid} claim, so every one of those tests is really asking "can a caller reach another
 * tenant's data by changing a URL".
 */
class AccessTokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private final AuthzProperties properties = new AuthzProperties();

    private RSAKey signingKey;
    private AccessTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        properties.setIssuerBaseUrl("https://id.acme.test");
        signingKey = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        JwksSupplier supplier = tenant -> new JWKSet(List.of(signingKey.toPublicJWK()));
        verifier = new AccessTokenVerifier(supplier, properties, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void aValidTokenYieldsTheCallerItDescribes() {
        String token = token(claims().build());

        Caller caller = verifier.verify(token, "acme").orElseThrow();

        assertThat(caller.subject()).isEqualTo("user-1");
        assertThat(caller.tenantId()).isEqualTo(TENANT);
        assertThat(caller.scopes()).containsExactly("authz.check", "authz.write");
        assertThat(caller.hasScope("authz.check")).isTrue();
        assertThat(caller.hasScope("authz.admin")).isFalse();
    }

    @Test
    void aTokenWithNoScopesYieldsACallerWithNoPrivileges() {
        Caller caller = verifier.verify(token(claims().claim("scope", null).build()), "acme").orElseThrow();

        assertThat(caller.scopes()).isEmpty();
    }

    /** The tenant comes from the signed claim; a token minted for another tenant's issuer fails. */
    @Test
    void aTokenIssuedForAnotherTenantIsRejected() {
        String token = token(claims().issuer("https://id.acme.test/t/other").build());

        assertThat(verifier.verify(token, "acme")).isEmpty();
    }

    @Test
    void aTokenPresentedAtAnotherTenantsPathIsRejected() {
        String token = token(claims().build());

        assertThat(verifier.verify(token, "acme")).isPresent();
        assertThat(verifier.verify(token, "beta")).isEmpty();
    }

    @Test
    void aTokenWithNoTenantClaimIsRejected() {
        assertThat(verifier.verify(token(claims().claim("tid", null).build()), "acme")).isEmpty();
    }

    @Test
    void aTokenWhoseTenantClaimIsNotAUuidIsRejected() {
        assertThat(verifier.verify(token(claims().claim("tid", "../../etc/passwd").build()), "acme"))
                .isEmpty();
    }

    @Test
    void anExpiredTokenIsRejected() {
        String token = token(claims().expirationTime(Date.from(NOW.minusSeconds(1))).build());

        assertThat(verifier.verify(token, "acme")).isEmpty();
    }

    @Test
    void aTokenWithNoExpiryIsRejected() {
        assertThat(verifier.verify(token(claims().expirationTime(null).build()), "acme")).isEmpty();
    }

    @Test
    void anUnsignedTokenIsRejected() {
        String header = base64Url("{\"alg\":\"none\",\"kid\":\"kid-1\"}");
        String payload = base64Url("{\"iss\":\"https://id.acme.test/t/acme\",\"sub\":\"attacker\"}");

        assertThat(verifier.verify(header + "." + payload + ".", "acme")).isEmpty();
    }

    @Test
    void aTokenReSignedWithHmacIsRejected() throws Exception {
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("kid-1").build(), claims().build());
        forged.sign(new MACSigner(signingKey.toPublicJWK().toJSONString()
                .getBytes(StandardCharsets.UTF_8)));

        assertThat(verifier.verify(forged.serialize(), "acme")).isEmpty();
    }

    @Test
    void aTokenSignedByAnUnpublishedKeyIsRejected() throws Exception {
        RSAKey attackersKey = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-1").build(), claims().build());
        forged.sign(new RSASSASigner(attackersKey));

        assertThat(verifier.verify(forged.serialize(), "acme")).isEmpty();
    }

    @Test
    void aTokenNamingAKidThatIsNotPublishedIsRejected() throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-unknown").build(), claims().build());
        jwt.sign(new RSASSASigner(signingKey));

        assertThat(verifier.verify(jwt.serialize(), "acme")).isEmpty();
    }

    @Test
    void aTokenWithNoKidIsRejected() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims().build());
        jwt.sign(new RSASSASigner(signingKey));

        assertThat(verifier.verify(jwt.serialize(), "acme")).isEmpty();
    }

    @Test
    void garbageIsRejectedWithoutThrowing() {
        assertThat(verifier.verify("not-a-token", "acme")).isEmpty();
        assertThat(verifier.verify("", "acme")).isEmpty();
    }

    /** If the identity service is unreachable, this one cannot tell real tokens from forged ones. */
    @Test
    void anUnreachableIdentityServiceFailsClosed() {
        AccessTokenVerifier failing = new AccessTokenVerifier(
                tenant -> {
                    throw new IllegalStateException("connection refused");
                },
                properties, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThat(failing.verify(token(claims().build()), "acme")).isEmpty();
    }

    private JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .issuer("https://id.acme.test/t/acme")
                .subject("user-1")
                .expirationTime(Date.from(NOW.plusSeconds(600)))
                .claim("tid", TENANT.toString())
                .claim("scope", "authz.check authz.write");
    }

    private String token(JWTClaimsSet claims) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-1").build(), claims);
            jwt.sign(new RSASSASigner(signingKey));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
