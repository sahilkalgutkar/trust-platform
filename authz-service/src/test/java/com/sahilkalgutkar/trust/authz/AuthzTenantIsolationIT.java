package com.sahilkalgutkar.trust.authz;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The tenant boundary in the authorization service.
 *
 * <p>Both tenants use the same namespace name, the same object id, and the same subject, so any
 * query that lost its tenant predicate would return the other tenant's tuple and one of these
 * checks would come back allowed.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthzTenantIsolationIT extends AbstractAuthzIT {

    private static final UUID ALPHA = UUID.fromString("33333333-3333-3333-3333-333333333333");
    private static final UUID BETA = UUID.fromString("44444444-4444-4444-4444-444444444444");

    private String alphaToken;
    private String betaToken;

    @BeforeAll
    void provision() {
        alphaToken = tokenFor("iso-alpha", ALPHA, "authz.check authz.write");
        betaToken = tokenFor("iso-beta", BETA, "authz.check authz.write");

        writeNamespace("iso-alpha", alphaToken);
        writeNamespace("iso-beta", betaToken);

        // The identical relationship, written into each tenant only for alpha's user.
        write("iso-alpha", alphaToken, "document", "shared-name", "owner", "user:ada");
    }

    @Test
    void aTupleWrittenInOneTenantIsInvisibleInTheOther() {
        assertThat(check("iso-alpha", alphaToken, "document", "shared-name", "owner", "user:ada")).isTrue();
        assertThat(check("iso-beta", betaToken, "document", "shared-name", "owner", "user:ada")).isFalse();
    }

    @Test
    void bothTenantsCanUseTheSameNamespaceAndObjectNamesIndependently() {
        write("iso-beta", betaToken, "document", "shared-name", "owner", "user:bob");

        assertThat(check("iso-beta", betaToken, "document", "shared-name", "owner", "user:bob")).isTrue();
        assertThat(check("iso-alpha", alphaToken, "document", "shared-name", "owner", "user:bob")).isFalse();
    }

    @Test
    void aTokenForOneTenantIsRejectedOnTheOthersPath() {
        ResponseEntity<String> response = postRaw("/t/iso-beta/v1/check", alphaToken,
                Map.of("namespace", "document", "object", "shared-name", "relation", "owner",
                        "subject", "user:ada"));

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void aNamespaceIsScopedToTheTenantThatDefinedIt() {
        writeNamespaceNamed("iso-alpha", alphaToken, "alpha-only");

        ResponseEntity<String> inOwner = rest.exchange("/t/iso-alpha/v1/namespaces/alpha-only",
                HttpMethod.GET, new HttpEntity<>(bearer(alphaToken)), String.class);
        ResponseEntity<String> inOther = rest.exchange("/t/iso-beta/v1/namespaces/alpha-only",
                HttpMethod.GET, new HttpEntity<>(bearer(betaToken)), String.class);

        assertThat(inOwner.getStatusCode().value()).isEqualTo(200);
        assertThat(inOther.getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void listingNamespacesShowsOnlyTheCallersTenant() {
        writeNamespaceNamed("iso-alpha", alphaToken, "alpha-listed");

        ResponseEntity<String> betaList = rest.exchange("/t/iso-beta/v1/namespaces",
                HttpMethod.GET, new HttpEntity<>(bearer(betaToken)), String.class);

        assertThat(betaList.getBody()).doesNotContain("alpha-listed");
    }

    @Test
    void expandingInOneTenantDoesNotRevealTheOthersSubjects() {
        write("iso-alpha", alphaToken, "document", "expand-me", "owner", "user:alpha-only");

        ResponseEntity<String> response = postRaw("/t/iso-beta/v1/expand", betaToken,
                Map.of("namespace", "document", "object", "expand-me", "relation", "owner"));

        assertThat(response.getBody()).doesNotContain("user:alpha-only");
    }

    /** A zookie is a revision from a shared sequence; holding one grants nothing on its own. */
    @Test
    void aZookieFromOneTenantDoesNotUnlockAnythingInTheOther() {
        String alphaZookie = write("iso-alpha", alphaToken, "document", "zookie-test", "owner", "user:ada");

        Map<String, Object> betaCheck = checkResponse("iso-beta", betaToken, "document", "zookie-test",
                "owner", "user:ada", alphaZookie);

        assertThat(betaCheck).containsEntry("allowed", false);
    }

    // ------------------------------------------------------------------ helpers

    private void writeNamespace(String slug, String token) {
        writeNamespaceNamed(slug, token, "document");
    }

    private void writeNamespaceNamed(String slug, String token, String name) {
        ResponseEntity<String> response = postRaw("/t/" + slug + "/v1/namespaces", token,
                Map.of("name", name, "relations", Map.of(
                        "owner", Map.of("type", "this"),
                        "viewer", Map.of("type", "union", "children", List.of(
                                Map.of("type", "this"),
                                Map.of("type", "computedUserset", "relation", "owner"))))));
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Could not write namespace: " + response.getBody());
        }
    }

    private String write(String slug, String token, String namespace, String object, String relation,
                         String subject) {
        ResponseEntity<Map<String, Object>> response = post("/t/" + slug + "/v1/tuples", token,
                Map.of("changes", List.of(Map.of("operation", "WRITE", "namespace", namespace,
                        "object", object, "relation", relation, "subject", subject))));
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Tuple write failed: " + response.getBody());
        }
        return (String) response.getBody().get("zookie");
    }

    private boolean check(String slug, String token, String namespace, String object, String relation,
                          String subject) {
        return (Boolean) checkResponse(slug, token, namespace, object, relation, subject, null)
                .get("allowed");
    }

    private Map<String, Object> checkResponse(String slug, String token, String namespace, String object,
                                              String relation, String subject, String zookie) {
        java.util.Map<String, String> body = new java.util.HashMap<>(Map.of(
                "namespace", namespace, "object", object, "relation", relation, "subject", subject));
        if (zookie != null) {
            body.put("zookie", zookie);
        }
        ResponseEntity<Map<String, Object>> response = post("/t/" + slug + "/v1/check", token, body);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Check failed: " + response.getBody());
        }
        return response.getBody();
    }
}
