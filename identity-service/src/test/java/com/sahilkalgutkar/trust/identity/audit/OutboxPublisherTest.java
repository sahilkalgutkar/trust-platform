package com.sahilkalgutkar.trust.identity.audit;

import com.sahilkalgutkar.trust.common.audit.AuditTopics;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.identity.repo.AuditOutboxRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OutboxPublisherTest {

    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");
    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");

    @SuppressWarnings("unchecked")
    private final KafkaTemplate<String, String> kafka = mock(KafkaTemplate.class);
    private final AuditOutboxRepository repository = mock(AuditOutboxRepository.class);
    private final IdentityProperties properties = new IdentityProperties();

    private OutboxPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new OutboxPublisher(repository, kafka, properties, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void pendingEntriesArePublishedAndMarked() {
        AuditOutboxEntity entry = new AuditOutboxEntity(UUID.randomUUID(), TENANT, "{\"action\":\"token.issued\"}");
        when(repository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc()).thenReturn(List.of(entry));
        when(kafka.send(anyString(), anyString(), anyString())).thenReturn(succeeded());

        publisher.drain();

        verify(kafka).send(AuditTopics.AUDIT_EVENTS, TENANT.toString(), entry.getPayload());
        assertThat(entry.getPublishedAt()).isEqualTo(NOW);
        verify(repository).save(entry);
    }

    /** The tenant is the partition key, so one tenant's events stay in the order they were written. */
    @Test
    void theTenantIsUsedAsThePartitionKey() {
        AuditOutboxEntity entry = new AuditOutboxEntity(UUID.randomUUID(), TENANT, "{}");
        when(repository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc()).thenReturn(List.of(entry));
        when(kafka.send(anyString(), anyString(), anyString())).thenReturn(succeeded());

        publisher.drain();

        verify(kafka).send(anyString(), eq(TENANT.toString()), anyString());
    }

    /**
     * A failed send stops the drain rather than skipping the entry: continuing would publish later
     * events before an earlier one, and the consumer chains them in arrival order.
     */
    @Test
    void aFailedSendStopsTheDrainSoOrderingSurvivesTheRetry() {
        AuditOutboxEntity first = new AuditOutboxEntity(UUID.randomUUID(), TENANT, "{\"seq\":1}");
        AuditOutboxEntity second = new AuditOutboxEntity(UUID.randomUUID(), TENANT, "{\"seq\":2}");
        when(repository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc())
                .thenReturn(List.of(first, second));
        when(kafka.send(anyString(), anyString(), eq("{\"seq\":1}"))).thenReturn(failed());

        publisher.drain();

        assertThat(first.getPublishedAt()).isNull();
        assertThat(second.getPublishedAt()).isNull();
        verify(kafka, never()).send(anyString(), anyString(), eq("{\"seq\":2}"));
    }

    @Test
    void anEmptyOutboxTouchesKafkaNotAtAll() {
        when(repository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc()).thenReturn(List.of());

        publisher.drain();

        verify(kafka, never()).send(anyString(), anyString(), anyString());
    }

    @Test
    void publishingCanBeTurnedOffEntirely() {
        properties.setAuditPublishingEnabled(false);

        publisher.drain();

        verify(repository, never()).findTop200ByPublishedAtIsNullOrderByCreatedAtAsc();
    }

    private static CompletableFuture<SendResult<String, String>> succeeded() {
        return CompletableFuture.completedFuture(null);
    }

    private static CompletableFuture<SendResult<String, String>> failed() {
        return CompletableFuture.failedFuture(new IllegalStateException("broker unavailable"));
    }
}
