package com.sahilkalgutkar.trust.authz;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sahilkalgutkar.trust.authz.config.JwksSupplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Base for the authorization service's integration tests: real Postgres, real Redis, real Hibernate
 * multi-tenancy — and a locally generated signing key standing in for the identity service.
 *
 * <p>Substituting the key source rather than running the identity service is the right seam. What
 * these tests are about is what the authorization service does with a <em>valid</em> token; that a
 * forged one is rejected is settled by {@code AccessTokenVerifierTest}, and running a second
 * service here would only add a way for these tests to fail for unrelated reasons.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(AbstractAuthzIT.TestKeys.class)
public abstract class AbstractAuthzIT {

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("trust_authz")
                    .withUsername("trust")
                    .withPassword("trust");

    private static final GenericContainer<?> REDIS =
            new GenericContainer<>("redis:7-alpine").withExposedPorts(6379);

    static final RSAKey SIGNING_KEY = generateKey();
    static final String ISSUER_BASE = "https://id.test";

    static {
        POSTGRES.start();
        REDIS.start();
    }

    @Autowired
    protected TestRestTemplate rest;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("trust.authz.issuer-base-url", () -> ISSUER_BASE);
        registry.add("trust.authz.audit-publishing-enabled", () -> "false");
    }

    @TestConfiguration
    public static class TestKeys {

        @Bean
        @Primary
        public JwksSupplier testJwksSupplier() {
            return tenant -> new JWKSet(List.of(SIGNING_KEY.toPublicJWK()));
        }
    }

    // ------------------------------------------------------------------ helpers

    protected static String tokenFor(String tenantSlug, UUID tenantId, String scope) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER_BASE + "/t/" + tenantSlug)
                .subject("ada")
                .expirationTime(Date.from(Instant.now().plusSeconds(600)))
                .claim("tid", tenantId.toString())
                .claim("scope", scope)
                .build();
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SIGNING_KEY.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(SIGNING_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Could not mint a test token", e);
        }
    }

    protected static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);
        return headers;
    }

    @SuppressWarnings("unchecked")
    protected <T> ResponseEntity<Map<String, Object>> post(String path, String token, T body) {
        return (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) rest.exchange(path,
                HttpMethod.POST, new HttpEntity<>(body, bearer(token)), Map.class);
    }

    protected ResponseEntity<String> postRaw(String path, String token, Object body) {
        return rest.exchange(path, HttpMethod.POST, new HttpEntity<>(body, bearer(token)), String.class);
    }

    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("test-kid").generate();
        } catch (Exception e) {
            throw new IllegalStateException("Could not generate a test signing key", e);
        }
    }
}
