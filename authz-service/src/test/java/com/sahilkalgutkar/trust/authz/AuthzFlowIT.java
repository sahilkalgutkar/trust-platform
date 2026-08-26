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

/** The authorization API end to end, against real Postgres and real Redis. */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AuthzFlowIT extends AbstractAuthzIT {

    private static final String TENANT_SLUG = "flow";
    private static final UUID TENANT_ID = UUID.fromString("22222222-2222-2222-2222-222222222222");

    private String writeToken;
    private String checkToken;

    @BeforeAll
    void provisionNamespaces() {
        writeToken = tokenFor(TENANT_SLUG, TENANT_ID, "authz.check authz.write");
        checkToken = tokenFor(TENANT_SLUG, TENANT_ID, "authz.check");

        writeNamespace("group", Map.of("member", Map.of("type", "this")));
        writeNamespace("folder", Map.of(
                "parent", Map.of("type", "this"),
                "viewer", Map.of("type", "union", "children", List.of(
                        Map.of("type", "this"),
                        Map.of("type", "tupleToUserset", "tupleset", "parent", "computedUserset", "viewer")))));
        writeNamespace("document", Map.of(
                "parent", Map.of("type", "this"),
                "owner", Map.of("type", "this"),
                "editor", Map.of("type", "union", "children", List.of(
                        Map.of("type", "this"),
                        Map.of("type", "computedUserset", "relation", "owner"))),
                "viewer", Map.of("type", "union", "children", List.of(
                        Map.of("type", "this"),
                        Map.of("type", "computedUserset", "relation", "editor"),
                        Map.of("type", "tupleToUserset", "tupleset", "parent", "computedUserset", "viewer")))));
    }

    @Test
    void aNamespaceRoundTripsThroughStorage() {
        ResponseEntity<Map<String, Object>> response = (ResponseEntity<Map<String, Object>>)
                (ResponseEntity<?>) rest.exchange("/t/" + TENANT_SLUG + "/v1/namespaces/document",
                        HttpMethod.GET, new HttpEntity<>(bearer(checkToken)), Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().get("relations").toString())
                .contains("owner").contains("tupleToUserset");
    }

    @Test
    void aWrittenRelationshipMakesTheCheckPass() {
        write("WRITE", "document", "readme", "owner", "user:ada");

        assertThat(check("document", "readme", "owner", "user:ada", null)).isTrue();
        assertThat(check("document", "readme", "owner", "user:bob", null)).isFalse();
    }

    @Test
    void ownershipImpliesEditingAndViewing() {
        write("WRITE", "document", "design-doc", "owner", "user:ada");

        assertThat(check("document", "design-doc", "editor", "user:ada", null)).isTrue();
        assertThat(check("document", "design-doc", "viewer", "user:ada", null)).isTrue();
    }

    @Test
    void aDocumentInheritsViewersFromItsFolderChain() {
        write("WRITE", "folder", "company", "viewer", "user:carol");
        write("WRITE", "folder", "eng", "parent", "folder:company");
        write("WRITE", "document", "spec", "parent", "folder:eng");

        assertThat(check("document", "spec", "viewer", "user:carol", null)).isTrue();
    }

    @Test
    void groupMembershipReachesThroughToTheDocument() {
        write("WRITE", "group", "eng", "member", "user:dave");
        write("WRITE", "document", "handbook", "viewer", "group:eng#member");

        assertThat(check("document", "handbook", "viewer", "user:dave", null)).isTrue();
        assertThat(check("document", "handbook", "viewer", "user:erin", null)).isFalse();
    }

    @Test
    void deletingTheRelationshipRevokesTheAccess() {
        write("WRITE", "document", "secrets", "owner", "user:frank");
        assertThat(check("document", "secrets", "owner", "user:frank", null)).isTrue();

        String zookie = write("DELETE", "document", "secrets", "owner", "user:frank");

        assertThat(check("document", "secrets", "owner", "user:frank", zookie)).isFalse();
    }

    /**
     * The read-your-writes case. Without passing the zookie back, the check could legitimately be
     * served from a cache entry computed before the revoke — which is exactly the stale allow the
     * consistency token exists to prevent.
     */
    @Test
    void passingTheZookieFromAWriteGuaranteesTheCheckSeesIt() {
        write("WRITE", "document", "rota", "owner", "user:grace");
        assertThat(check("document", "rota", "owner", "user:grace", null)).isTrue();

        String zookie = write("DELETE", "document", "rota", "owner", "user:grace");

        assertThat(check("document", "rota", "owner", "user:grace", zookie)).isFalse();
    }

    @Test
    void aRepeatedCheckIsServedFromTheCache() {
        write("WRITE", "document", "cached", "owner", "user:heidi");
        Map<String, Object> first = checkResponse("document", "cached", "owner", "user:heidi", null);
        Map<String, Object> second = checkResponse("document", "cached", "owner", "user:heidi",
                (String) first.get("zookie"));

        assertThat(first.get("cached")).isEqualTo(false);
        assertThat(second.get("cached")).isEqualTo(true);
    }

    @Test
    void expandShowsWhySomeoneHasAccess() {
        write("WRITE", "document", "why", "owner", "user:ivan");
        write("WRITE", "document", "why", "viewer", "group:eng#member");

        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/expand", checkToken,
                Map.of("namespace", "document", "object", "why", "relation", "viewer"));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).contains("group:eng#member").contains("user:ivan");
    }

    @Test
    void awholeBatchOfChangesLandsAtOneRevision() {
        ResponseEntity<Map<String, Object>> response = post("/t/" + TENANT_SLUG + "/v1/tuples", writeToken,
                Map.of("changes", List.of(
                        Map.of("operation", "WRITE", "namespace", "document", "object", "batch",
                                "relation", "owner", "subject", "user:judy"),
                        Map.of("operation", "WRITE", "namespace", "document", "object", "batch",
                                "relation", "viewer", "subject", "user:ken"))));

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsEntry("applied", 2);
        assertThat(response.getBody().get("zookie")).isNotNull();
    }

    // ------------------------------------------------------------------ errors and authorization

    @Test
    void writingRequiresTheWriteScope() {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/tuples", checkToken,
                Map.of("changes", List.of(Map.of("operation", "WRITE", "namespace", "document",
                        "object", "nope", "relation", "owner", "subject", "user:ada"))));

        assertThat(response.getStatusCode().value()).isEqualTo(403);
        assertThat(response.getBody()).contains("insufficient_scope");
    }

    @Test
    void everyEndpointRequiresAToken() {
        ResponseEntity<String> response = rest.exchange("/t/" + TENANT_SLUG + "/v1/check",
                HttpMethod.POST, new HttpEntity<>(Map.of("namespace", "document", "object", "readme",
                        "relation", "owner", "subject", "user:ada")), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    void aRelationTheNamespaceDoesNotDefineIsA400NotADenial() {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/check", checkToken,
                Map.of("namespace", "document", "object", "readme", "relation", "administer",
                        "subject", "user:ada"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody()).contains("unknown_relation");
    }

    @Test
    void anUnknownNamespaceIsA404() {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/check", checkToken,
                Map.of("namespace", "spaceship", "object", "readme", "relation", "owner",
                        "subject", "user:ada"));

        assertThat(response.getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void aMalformedSubjectIsRejected() {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/check", checkToken,
                Map.of("namespace", "document", "object", "readme", "relation", "owner",
                        "subject", "not-a-subject"));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void aNamespaceWithADanglingReferenceIsRejectedAtWriteTime() {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/namespaces", writeToken,
                Map.of("name", "broken", "relations", Map.of(
                        "viewer", Map.of("type", "computedUserset", "relation", "nonexistent"))));

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    // ------------------------------------------------------------------ helpers

    private void writeNamespace(String name, Map<String, Object> relations) {
        ResponseEntity<String> response = postRaw("/t/" + TENANT_SLUG + "/v1/namespaces", writeToken,
                Map.of("name", name, "relations", relations));
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Could not write namespace " + name + ": " + response.getBody());
        }
    }

    private String write(String operation, String namespace, String object, String relation,
                         String subject) {
        ResponseEntity<Map<String, Object>> response = post("/t/" + TENANT_SLUG + "/v1/tuples", writeToken,
                Map.of("changes", List.of(Map.of("operation", operation, "namespace", namespace,
                        "object", object, "relation", relation, "subject", subject))));
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Tuple write failed: " + response.getBody());
        }
        return (String) response.getBody().get("zookie");
    }

    private boolean check(String namespace, String object, String relation, String subject,
                          String zookie) {
        return (Boolean) checkResponse(namespace, object, relation, subject, zookie).get("allowed");
    }

    private Map<String, Object> checkResponse(String namespace, String object, String relation,
                                              String subject, String zookie) {
        java.util.Map<String, String> body = new java.util.HashMap<>(Map.of(
                "namespace", namespace, "object", object, "relation", relation, "subject", subject));
        if (zookie != null) {
            body.put("zookie", zookie);
        }
        ResponseEntity<Map<String, Object>> response = post("/t/" + TENANT_SLUG + "/v1/check",
                checkToken, body);
        if (!response.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("Check failed: " + response.getBody());
        }
        return response.getBody();
    }
}
