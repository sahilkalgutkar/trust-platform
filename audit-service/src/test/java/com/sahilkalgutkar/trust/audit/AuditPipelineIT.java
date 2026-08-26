package com.sahilkalgutkar.trust.audit;

import com.sahilkalgutkar.trust.audit.chain.ChainHead;
import com.sahilkalgutkar.trust.audit.chain.ChainVerification;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import com.sahilkalgutkar.trust.common.audit.AuditTopics;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.kafka.KafkaContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * The audit pipeline end to end: Kafka in, chain out, and a tamper detected.
 *
 * <p>The last test is the one this whole service exists for. It does what an attacker with database
 * access would do — a plain SQL UPDATE against a stored record — and asserts that verification names
 * the exact row. Nothing short of a real database proves that, because the thing being defended
 * against is someone editing the real database.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuditPipelineIT {

    private static final String ADMIN_KEY = "integration-test-admin-key";

    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("trust_audit")
                    .withUsername("trust")
                    .withPassword("trust");

    private static final KafkaContainer KAFKA = new KafkaContainer("apache/kafka:3.8.0");

    static {
        POSTGRES.start();
        KAFKA.start();
    }

    @Autowired
    private TestRestTemplate rest;

    @Autowired
    private KafkaTemplate<String, String> kafka;

    @Autowired
    private JdbcTemplate jdbc;

    @DynamicPropertySource
    static void configure(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.kafka.bootstrap-servers", KAFKA::getBootstrapServers);
        registry.add("spring.kafka.producer.key-serializer",
                () -> "org.apache.kafka.common.serialization.StringSerializer");
        registry.add("spring.kafka.producer.value-serializer",
                () -> "org.apache.kafka.common.serialization.StringSerializer");
        registry.add("trust.audit.admin-api-key", () -> ADMIN_KEY);
    }

    @Test
    void eventsProducedToKafkaBecomeAChain() {
        UUID tenant = UUID.randomUUID();

        publish(tenant, "evt-1", "token.issued", "user:ada");
        publish(tenant, "evt-2", "refresh.reuse_detected", "client:web-app");
        publish(tenant, "evt-3", "tuple.write", "user:admin");

        awaitChainLength(tenant, 3);

        List<?> events = readEvents(tenant);
        assertThat(events).hasSize(3);
        assertThat(events.toString())
                .contains("token.issued")
                .contains("refresh.reuse_detected")
                .contains("tuple.write");
    }

    @Test
    void aRedeliveredEventIsNotChainedTwice() {
        UUID tenant = UUID.randomUUID();

        publish(tenant, "dup-1", "token.issued", "user:ada");
        awaitChainLength(tenant, 1);

        publish(tenant, "dup-1", "token.issued", "user:ada");
        publish(tenant, "dup-2", "token.refreshed", "user:ada");
        awaitChainLength(tenant, 2);

        assertThat(head(tenant).seq()).isEqualTo(2);
    }

    @Test
    void anIntactChainVerifies() {
        UUID tenant = UUID.randomUUID();
        for (int i = 1; i <= 5; i++) {
            publish(tenant, "ok-" + i, "token.issued", "user:ada");
        }
        awaitChainLength(tenant, 5);

        ChainVerification verification = verify(tenant);

        assertThat(verification.intact()).isTrue();
        assertThat(verification.recordsChecked()).isEqualTo(5);
        assertThat(verification.headHash()).isEqualTo(head(tenant).hash());
    }

    /** The attack, carried out for real: UPDATE the audit table and see whether anyone notices. */
    @Test
    void editingAStoredRecordWithSqlIsDetected() {
        UUID tenant = UUID.randomUUID();
        for (int i = 1; i <= 4; i++) {
            publish(tenant, "tamper-" + i, "token.issued", "user:ada");
        }
        awaitChainLength(tenant, 4);
        assertThat(verify(tenant).intact()).isTrue();

        int updated = jdbc.update(
                "UPDATE audit_events SET actor = ? WHERE tenant_id = ? AND seq = ?",
                "user:someone-else", tenant, 2L);
        assertThat(updated).isEqualTo(1);

        ChainVerification verification = verify(tenant);

        assertThat(verification.intact()).isFalse();
        assertThat(verification.brokenAtSeq()).isEqualTo(2);
        assertThat(verification.reason()).contains("Indexed columns disagree");
    }

    @Test
    void deletingAStoredRecordWithSqlIsDetected() {
        UUID tenant = UUID.randomUUID();
        for (int i = 1; i <= 4; i++) {
            publish(tenant, "delete-" + i, "token.issued", "user:ada");
        }
        awaitChainLength(tenant, 4);

        jdbc.update("DELETE FROM audit_events WHERE tenant_id = ? AND seq = ?", tenant, 3L);

        ChainVerification verification = verify(tenant);

        assertThat(verification.intact()).isFalse();
        assertThat(verification.brokenAtSeq()).isEqualTo(3);
        assertThat(verification.reason()).contains("Missing record at position 3");
    }

    @Test
    void rewritingThePayloadOfAStoredRecordIsDetected() {
        UUID tenant = UUID.randomUUID();
        for (int i = 1; i <= 3; i++) {
            publish(tenant, "payload-" + i, "token.issued", "user:ada");
        }
        awaitChainLength(tenant, 3);

        jdbc.update("UPDATE audit_events SET payload = ? WHERE tenant_id = ? AND seq = ?",
                "{\"eventId\":\"payload-1\",\"tenantId\":\"" + tenant + "\",\"action\":\"nothing.happened\"}",
                tenant, 1L);

        assertThat(verify(tenant).intact()).isFalse();
        assertThat(verify(tenant).brokenAtSeq()).isEqualTo(1);
    }

    @Test
    void tenantsHaveSeparateChainsThatDoNotInterleave() {
        UUID alpha = UUID.randomUUID();
        UUID beta = UUID.randomUUID();

        publish(alpha, "a-1", "token.issued", "user:ada");
        publish(beta, "b-1", "token.issued", "user:bob");
        publish(alpha, "a-2", "token.refreshed", "user:ada");

        awaitChainLength(alpha, 2);
        awaitChainLength(beta, 1);

        assertThat(verify(alpha).intact()).isTrue();
        assertThat(verify(beta).intact()).isTrue();
        assertThat(head(alpha).hash()).isNotEqualTo(head(beta).hash());
    }

    @Test
    void anUnparseableMessageDoesNotStopTheConsumer() {
        UUID tenant = UUID.randomUUID();

        kafka.send(AuditTopics.AUDIT_EVENTS, tenant.toString(), "{ this is not an audit event");
        publish(tenant, "after-poison", "token.issued", "user:ada");

        awaitChainLength(tenant, 1);
        assertThat(verify(tenant).intact()).isTrue();
    }

    @Test
    void theReadApiRequiresTheAdminKey() {
        UUID tenant = UUID.randomUUID();

        ResponseEntity<String> response = rest.exchange(
                "/admin/tenants/" + tenant + "/audit/head", HttpMethod.GET,
                new HttpEntity<>(new HttpHeaders()), String.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    // ------------------------------------------------------------------ helpers

    private void publish(UUID tenant, String eventId, String action, String actor) {
        AuditEvent event = AuditEvent.builder(tenant.toString(), action)
                .eventId(eventId)
                .actor(actor)
                .outcome(AuditOutcome.SUCCESS)
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .build();
        kafka.send(AuditTopics.AUDIT_EVENTS, tenant.toString(), CanonicalJson.string(event));
    }

    private void awaitChainLength(UUID tenant, long expected) {
        await().atMost(Duration.ofSeconds(30))
                .pollInterval(Duration.ofMillis(200))
                .untilAsserted(() -> assertThat(head(tenant).seq()).isEqualTo(expected));
    }

    private ChainHead head(UUID tenant) {
        return rest.exchange("/admin/tenants/" + tenant + "/audit/head", HttpMethod.GET,
                new HttpEntity<>(adminHeaders()), ChainHead.class).getBody();
    }

    private ChainVerification verify(UUID tenant) {
        return rest.exchange("/admin/tenants/" + tenant + "/audit/verify", HttpMethod.POST,
                new HttpEntity<>(adminHeaders()), ChainVerification.class).getBody();
    }

    private List<?> readEvents(UUID tenant) {
        return rest.exchange("/admin/tenants/" + tenant + "/audit/events?limit=50", HttpMethod.GET,
                new HttpEntity<>(adminHeaders()), List.class).getBody();
    }

    private static HttpHeaders adminHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Admin-Key", ADMIN_KEY);
        return headers;
    }
}
