package com.sahilkalgutkar.trust.identity.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Verifies tokens this provider issued.
 *
 * <p>Written as an explicit sequence of checks rather than a library one-liner because the checks
 * are the interesting part, and because the failures are famous:
 *
 * <ul>
 *   <li><b>{@code alg} is pinned to RS256.</b> Accepting whatever the header asks for is how
 *       {@code alg: none} and HS256-signed-with-the-public-key forgeries get in — the token would
 *       otherwise be telling the verifier how to verify it.</li>
 *   <li><b>{@code kid} must name a published key.</b> A retired-past-grace key stops verifying at
 *       the same moment it stops being published, with no separate expiry bookkeeping.</li>
 *   <li><b>{@code iss} must match the tenant's issuer exactly.</b> Combined with per-tenant keys,
 *       a token from another tenant fails twice over.</li>
 * </ul>
 */
@Component
public class JwtVerifier {

    private final SigningKeyService signingKeyService;
    private final Clock clock;

    public JwtVerifier(SigningKeyService signingKeyService, Clock clock) {
        this.signingKeyService = signingKeyService;
        this.clock = clock;
    }

    public Optional<JWTClaimsSet> verify(String token, String expectedIssuer) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException e) {
            return Optional.empty();
        }

        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            return Optional.empty();
        }

        String kid = jwt.getHeader().getKeyID();
        if (kid == null) {
            return Optional.empty();
        }
        Optional<RSAKey> key = signingKeyService.findVerificationKey(kid);
        if (key.isEmpty()) {
            return Optional.empty();
        }

        try {
            if (!jwt.verify(new RSASSAVerifier(key.get()))) {
                return Optional.empty();
            }
        } catch (JOSEException e) {
            return Optional.empty();
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            return Optional.empty();
        }

        if (!expectedIssuer.equals(claims.getIssuer())) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (claims.getExpirationTime() == null || !now.isBefore(claims.getExpirationTime().toInstant())) {
            return Optional.empty();
        }
        if (claims.getNotBeforeTime() != null && now.isBefore(claims.getNotBeforeTime().toInstant())) {
            return Optional.empty();
        }
        return Optional.of(claims);
    }
}
