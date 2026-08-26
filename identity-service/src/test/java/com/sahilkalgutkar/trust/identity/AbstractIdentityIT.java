package com.sahilkalgutkar.trust.identity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.testcontainers.containers.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * Base for the integration tests: a real Postgres, real Flyway migrations, real Hibernate
 * multi-tenancy.
 *
 * <p>These run against a database rather than a mock on purpose. The tenant discriminator, the
 * partial unique index that makes key rotation safe, and the uniqueness constraints that let two
 * tenants reuse a client id are all <em>database</em> behaviour — a mocked repository would happily
 * agree with whatever the service asked for and prove none of it.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class AbstractIdentityIT {

    protected static final String ADMIN_KEY = "integration-test-admin-key";

    /**
     * One container for the whole suite, started once and never stopped — Ryuk reaps it when the
     * JVM exits. Starting a Postgres per test class would triple the suite's wall clock for no
     * additional isolation, since each class provisions its own tenants.
     */
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("trust_identity")
                    .withUsername("trust")
                    .withPassword("trust");

    static {
        POSTGRES.start();
    }

    /**
     * TestRestTemplate does not follow redirects, which is what these tests need: the 302 out of
     * the authorization endpoint carries the authorization code, and following it would just fetch
     * a client callback that does not exist.
     */
    @Autowired
    protected TestRestTemplate rest;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("trust.identity.admin-api-key", () -> ADMIN_KEY);
        registry.add("trust.identity.master-key",
                () -> Base64.getEncoder().encodeToString(new byte[32]));
        // No broker in these tests: the outbox is asserted on directly, and its drain is what
        // needs Kafka, not the flows under test.
        registry.add("trust.identity.audit-publishing-enabled", () -> "false");
    }

    protected static HttpHeaders adminHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Admin-Key", ADMIN_KEY);
        return headers;
    }

    protected static HttpHeaders formHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return headers;
    }

    protected static HttpHeaders basicAuth(String clientId, String secret) {
        HttpHeaders headers = formHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8)));
        return headers;
    }

    protected static MultiValueMap<String, String> form(Map<String, String> values) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        values.forEach((key, value) -> {
            if (value != null) {
                form.add(key, value);
            }
        });
        return form;
    }

    @SuppressWarnings("unchecked")
    protected ResponseEntity<Map<String, Object>> postForm(String path, HttpHeaders headers,
                                                           Map<String, String> values) {
        return (ResponseEntity<Map<String, Object>>) (ResponseEntity<?>) rest.exchange(path,
                HttpMethod.POST, new HttpEntity<>(form(values), headers), Map.class);
    }

    // ------------------------------------------------------------------ provisioning helpers

    /** A tenant with one user and one client, ready to run a flow against. */
    protected record Fixture(String slug, String email, String password, String clientId,
                             String clientSecret, String redirectUri) {

        public String issuerPath() {
            return "/t/" + slug;
        }
    }

    protected Fixture provision(String slug, boolean confidential) {
        return provision(slug, confidential, "ada@acme.test", "web-app",
                "authorization_code,refresh_token");
    }

    @SuppressWarnings("unchecked")
    protected Fixture provision(String slug, boolean confidential, String email, String clientId,
                                String grantTypes) {
        String password = "correct horse battery staple";
        String redirectUri = "https://app." + slug + ".test/callback";

        ResponseEntity<Map> tenant = rest.exchange("/admin/tenants", HttpMethod.POST,
                new HttpEntity<>(Map.of("slug", slug, "name", slug + " Inc"), adminHeaders()), Map.class);
        if (!tenant.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Could not provision tenant " + slug + ": " + tenant.getBody());
        }

        rest.exchange("/t/" + slug + "/admin/users", HttpMethod.POST,
                new HttpEntity<>(Map.of("email", email, "password", password), adminHeaders()), Map.class);

        ResponseEntity<Map> client = rest.exchange("/t/" + slug + "/admin/clients", HttpMethod.POST,
                new HttpEntity<>(Map.of(
                        "clientId", clientId,
                        "name", "Web App",
                        "redirectUris", java.util.List.of(redirectUri),
                        "grantTypes", java.util.List.of(grantTypes.split(",")),
                        "scopes", java.util.List.of("openid", "profile"),
                        "confidential", confidential,
                        "requirePkce", true), adminHeaders()), Map.class);

        String secret = client.getBody() == null ? null : (String) client.getBody().get("client_secret");
        return new Fixture(slug, email, password, clientId, secret, redirectUri);
    }

    // ------------------------------------------------------------------ flow helpers

    protected static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    protected static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /** Runs the authorization request and returns the code out of the 302's Location header. */
    protected String authorizeForCode(Fixture fixture) {
        ResponseEntity<String> response = rest.exchange(fixture.issuerPath() + "/oauth2/authorize",
                HttpMethod.POST, new HttpEntity<>(form(Map.of(
                        "response_type", "code",
                        "client_id", fixture.clientId(),
                        "redirect_uri", fixture.redirectUri(),
                        "scope", "openid profile",
                        "state", "xyz",
                        "code_challenge", CHALLENGE,
                        "code_challenge_method", "S256",
                        "username", fixture.email(),
                        "password", fixture.password())), formHeaders()), String.class);

        if (response.getStatusCode().value() != 302) {
            throw new IllegalStateException("Expected a redirect but got " + response.getStatusCode()
                    + ": " + response.getBody());
        }
        return codeFrom(response.getHeaders().getLocation().toString());
    }

    protected static String codeFrom(String location) {
        return org.springframework.web.util.UriComponentsBuilder.fromUriString(location)
                .build().getQueryParams().getFirst("code");
    }

    protected HttpHeaders clientAuth(Fixture fixture) {
        return fixture.clientSecret() == null
                ? formHeaders()
                : basicAuth(fixture.clientId(), fixture.clientSecret());
    }

    protected ResponseEntity<Map<String, Object>> exchangeCode(Fixture fixture, String code) {
        return postForm(fixture.issuerPath() + "/oauth2/token", clientAuth(fixture), Map.of(
                "grant_type", "authorization_code",
                "code", code,
                "redirect_uri", fixture.redirectUri(),
                "code_verifier", VERIFIER,
                "client_id", fixture.clientId()));
    }

    protected ResponseEntity<Map<String, Object>> refresh(Fixture fixture, String refreshToken) {
        return postForm(fixture.issuerPath() + "/oauth2/token", clientAuth(fixture), Map.of(
                "grant_type", "refresh_token",
                "refresh_token", refreshToken,
                "client_id", fixture.clientId()));
    }
}
