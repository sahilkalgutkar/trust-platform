package com.sahilkalgutkar.trust.identity.jwt;

import com.nimbusds.jose.JOSEObjectType;
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
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The signing and verification path, including the forgeries it has to turn away.
 *
 * <p>Every negative case here is a real, published attack on JWT verifiers rather than an invented
 * one — which is the point of testing them: they all produce a token that <em>parses</em>, and a
 * verifier that trusts the header rather than its own policy accepts every one of them.
 */
class JwtIssuerVerifierTest {

    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final String ISSUER = "https://id.acme.test/t/acme";
    private static final String TENANT = "11111111-1111-1111-1111-111111111111";

    private RSAKey signingKey;
    private SigningKeyService signingKeyService;
    private JwtIssuer issuer;
    private JwtVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("kid-1").generate();
        signingKeyService = mock(SigningKeyService.class);
        when(signingKeyService.activeSigningKey()).thenReturn(signingKey);
        when(signingKeyService.findVerificationKey(anyString())).thenReturn(Optional.empty());
        when(signingKeyService.findVerificationKey("kid-1"))
                .thenReturn(Optional.of(signingKey.toPublicJWK()));
        when(signingKeyService.publishedKeySet())
                .thenReturn(new JWKSet(List.of(signingKey.toPublicJWK())));

        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        issuer = new JwtIssuer(signingKeyService, clock);
        verifier = new JwtVerifier(signingKeyService, clock);
    }

    @Test
    void anIssuedAccessTokenVerifiesAndCarriesTheExpectedClaims() throws Exception {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid profile",
                Duration.ofMinutes(15));

        JWTClaimsSet claims = verifier.verify(token, ISSUER).orElseThrow();
        assertThat(claims.getSubject()).isEqualTo("user-1");
        assertThat(claims.getAudience()).containsExactly("web-app");
        assertThat(claims.getClaim("tid")).isEqualTo(TENANT);
        assertThat(claims.getClaim("scope")).isEqualTo("openid profile");
        assertThat(claims.getClaim("client_id")).isEqualTo("web-app");
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getExpirationTime().toInstant()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(SignedJWT.parse(token).getHeader().getKeyID()).isEqualTo("kid-1");
    }

    /** RFC 9068: an access token says so in its header, so it cannot be mistaken for an ID token. */
    @Test
    void accessTokensAreTypedAsAtJwt() throws Exception {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid",
                Duration.ofMinutes(15));

        assertThat(SignedJWT.parse(token).getHeader().getType())
                .isEqualTo(new JOSEObjectType("at+jwt"));
    }

    @Test
    void anIdTokenCarriesTheNonceAndAuthTime() throws Exception {
        String token = issuer.issueIdToken(ISSUER, "user-1", "web-app", TENANT, "ada@acme.test",
                "n-0S6_WzA2Mj", NOW.minusSeconds(30), Duration.ofMinutes(15));

        JWTClaimsSet claims = verifier.verify(token, ISSUER).orElseThrow();
        assertThat(claims.getClaim("nonce")).isEqualTo("n-0S6_WzA2Mj");
        assertThat(claims.getClaim("email")).isEqualTo("ada@acme.test");
        assertThat(claims.getLongClaim("auth_time")).isEqualTo(NOW.minusSeconds(30).getEpochSecond());
    }

    @Test
    void anIdTokenOmitsTheNonceClaimWhenNoNonceWasRequested() throws Exception {
        String token = issuer.issueIdToken(ISSUER, "user-1", "web-app", TENANT, "ada@acme.test",
                null, NOW, Duration.ofMinutes(15));

        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getClaim("nonce")).isNull();
    }

    // ------------------------------------------------------------------ forgeries

    /** The {@code alg: none} downgrade — an unsigned token dressed as a signed one. */
    @Test
    void anUnsignedTokenIsRejected() {
        String header = base64Url("{\"alg\":\"none\",\"kid\":\"kid-1\"}");
        String payload = base64Url("{\"iss\":\"" + ISSUER + "\",\"sub\":\"attacker\",\"exp\":99999999999}");

        assertThat(verifier.verify(header + "." + payload + ".", ISSUER)).isEmpty();
    }

    /**
     * Algorithm confusion: the attacker re-signs with HS256, using the provider's own public key as
     * the shared secret. Pinning the algorithm is what defeats it.
     */
    @Test
    void aTokenReSignedWithHmacUsingThePublicKeyIsRejected() throws Exception {
        byte[] publicKeyAsSecret = signingKey.toPublicJWK().toJSONString().getBytes(StandardCharsets.UTF_8);
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("kid-1").build(),
                claims("attacker"));
        forged.sign(new MACSigner(publicKeyAsSecret));

        assertThat(verifier.verify(forged.serialize(), ISSUER)).isEmpty();
    }

    @Test
    void aTokenSignedByAKeyThisTenantDoesNotPublishIsRejected() throws Exception {
        RSAKey foreignKey = new RSAKeyGenerator(2048).keyID("kid-other").generate();
        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-other").build(), claims("attacker"));
        forged.sign(new RSASSASigner(foreignKey));

        assertThat(verifier.verify(forged.serialize(), ISSUER)).isEmpty();
    }

    @Test
    void aTokenWithNoKidIsRejected() throws Exception {
        SignedJWT unkeyed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claims("user-1"));
        unkeyed.sign(new RSASSASigner(signingKey));

        assertThat(verifier.verify(unkeyed.serialize(), ISSUER)).isEmpty();
    }

    @Test
    void aTokenWhosePayloadWasEditedAfterSigningIsRejected() throws Exception {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid",
                Duration.ofMinutes(15));
        String[] parts = token.split("\\.");
        String editedPayload = base64Url("{\"iss\":\"" + ISSUER + "\",\"sub\":\"admin\",\"exp\":99999999999}");

        assertThat(verifier.verify(parts[0] + "." + editedPayload + "." + parts[2], ISSUER)).isEmpty();
    }

    /** Cross-tenant replay: a genuine token, presented to a different tenant's issuer. */
    @Test
    void aTokenFromAnotherIssuerIsRejected() {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid",
                Duration.ofMinutes(15));

        assertThat(verifier.verify(token, "https://id.acme.test/t/other-tenant")).isEmpty();
    }

    @Test
    void anExpiredTokenIsRejected() {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid",
                Duration.ofMinutes(15));
        JwtVerifier later = new JwtVerifier(signingKeyService,
                Clock.fixed(NOW.plus(Duration.ofMinutes(16)), ZoneOffset.UTC));

        assertThat(later.verify(token, ISSUER)).isEmpty();
    }

    @Test
    void aTokenIsRejectedBeforeItsNotBeforeTime() {
        String token = issuer.issueAccessToken(ISSUER, "user-1", "web-app", TENANT, "openid",
                Duration.ofMinutes(15));
        JwtVerifier earlier = new JwtVerifier(signingKeyService,
                Clock.fixed(NOW.minusSeconds(60), ZoneOffset.UTC));

        assertThat(earlier.verify(token, ISSUER)).isEmpty();
    }

    @Test
    void aTokenWithNoExpiryIsRejectedRatherThanTreatedAsEternal() throws Exception {
        SignedJWT everlasting = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("kid-1").build(),
                new JWTClaimsSet.Builder().issuer(ISSUER).subject("user-1").build());
        everlasting.sign(new RSASSASigner(signingKey));

        assertThat(verifier.verify(everlasting.serialize(), ISSUER)).isEmpty();
    }

    @Test
    void anythingThatIsNotAJwtIsRejected() {
        assertThat(verifier.verify("not-a-token", ISSUER)).isEmpty();
        assertThat(verifier.verify("", ISSUER)).isEmpty();
    }

    private JWTClaimsSet claims(String subject) {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(subject)
                .expirationTime(Date.from(NOW.plusSeconds(600)))
                .build();
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
