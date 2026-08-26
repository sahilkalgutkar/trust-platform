package com.sahilkalgutkar.trust.authz.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Turns a bearer token into a {@link Caller}.
 *
 * <p>The important line in this class is where the tenant comes from: the {@code tid} claim, not
 * the request path. The path says which tenant's issuer to verify against; the token says which
 * tenant the caller actually belongs to; and if those disagree the request is rejected. A caller
 * therefore cannot reach another tenant's data by editing a URL, because the tenant used for every
 * downstream query is the one the identity service signed.
 */
@Component
public class AccessTokenVerifier {

    private final JwksSupplier jwksSupplier;
    private final AuthzProperties properties;
    private final Clock clock;

    public AccessTokenVerifier(JwksSupplier jwksSupplier, AuthzProperties properties, Clock clock) {
        this.jwksSupplier = jwksSupplier;
        this.properties = properties;
        this.clock = clock;
    }

    public Optional<Caller> verify(String bearerToken, String tenantSlug) {
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(bearerToken);
        } catch (ParseException e) {
            return Optional.empty();
        }

        // Pinned, not read from the header: a token must not get to choose how it is verified.
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm()) || jwt.getHeader().getKeyID() == null) {
            return Optional.empty();
        }

        Optional<RSAKey> key = findKey(tenantSlug, jwt.getHeader().getKeyID());
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

        if (!properties.issuerFor(tenantSlug).equals(claims.getIssuer())) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        if (claims.getExpirationTime() == null || !now.isBefore(claims.getExpirationTime().toInstant())) {
            return Optional.empty();
        }

        Object tid = claims.getClaim("tid");
        if (tid == null) {
            return Optional.empty();
        }
        UUID tenantId;
        try {
            tenantId = UUID.fromString(tid.toString());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }

        return Optional.of(new Caller(claims.getSubject(), tenantId, scopes(claims)));
    }

    private Optional<RSAKey> findKey(String tenantSlug, String kid) {
        try {
            return jwksSupplier.forTenant(tenantSlug).getKeys().stream()
                    .filter(jwk -> kid.equals(jwk.getKeyID()))
                    .filter(RSAKey.class::isInstance)
                    .map(RSAKey.class::cast)
                    .findFirst();
        } catch (RuntimeException jwksUnavailable) {
            // Failing closed is the only defensible choice here: an unreachable identity service
            // means this one cannot tell a valid token from a forged one.
            return Optional.empty();
        }
    }

    private static Set<String> scopes(JWTClaimsSet claims) {
        Object scope = claims.getClaim("scope");
        if (scope == null) {
            return Set.of();
        }
        return Arrays.stream(scope.toString().trim().split("\\s+"))
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
    }

    /** Convenience for callers that only hold a {@link JWK} list, used by the tests. */
    public static boolean isRsa(JWK jwk) {
        return jwk instanceof RSAKey;
    }
}
