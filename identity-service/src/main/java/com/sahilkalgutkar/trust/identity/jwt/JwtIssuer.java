package com.sahilkalgutkar.trust.identity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/** Mints the RS256 access and ID tokens. */
@Component
public class JwtIssuer {

    /**
     * RFC 9068. Typing access tokens explicitly is what stops a resource server from accepting an
     * ID token as an access token — they are both valid signed JWTs from the same issuer, and the
     * only thing distinguishing them is what they are meant for.
     */
    private static final JOSEObjectType ACCESS_TOKEN_TYPE = new JOSEObjectType("at+jwt");

    private final SigningKeyService signingKeyService;
    private final Clock clock;

    public JwtIssuer(SigningKeyService signingKeyService, Clock clock) {
        this.signingKeyService = signingKeyService;
        this.clock = clock;
    }

    public String issueAccessToken(String issuer, String subject, String clientId, String tenantId,
                                   String scope, Duration ttl) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .claim("tid", tenantId)
                .claim("client_id", clientId)
                .claim("scope", scope)
                .build();
        return sign(claims, ACCESS_TOKEN_TYPE);
    }

    public String issueIdToken(String issuer, String subject, String clientId, String tenantId,
                               String email, String nonce, Instant authTime, Duration ttl) {
        Instant now = clock.instant();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(ttl)))
                .claim("tid", tenantId)
                .claim("email", email)
                .claim("auth_time", authTime.getEpochSecond());
        // Echoing the nonce is what ties this ID token to the exact authorization request the
        // client started, so a token replayed from another session fails the client's own check.
        if (nonce != null && !nonce.isBlank()) {
            claims.claim("nonce", nonce);
        }
        return sign(claims.build(), JOSEObjectType.JWT);
    }

    private String sign(JWTClaimsSet claims, JOSEObjectType type) {
        RSAKey key = signingKeyService.activeSigningKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(key.getKeyID())
                .type(type)
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(new RSASSASigner(key.toRSAPrivateKey()));
        } catch (JOSEException e) {
            throw new IllegalStateException("Unable to sign token", e);
        }
        return jwt.serialize();
    }
}
