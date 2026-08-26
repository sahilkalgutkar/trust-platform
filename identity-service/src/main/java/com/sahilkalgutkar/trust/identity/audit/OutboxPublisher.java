package com.sahilkalgutkar.trust.identity.audit;

import com.sahilkalgutkar.trust.common.audit.AuditTopics;
import com.sahilkalgutkar.trust.identity.config.IdentityProperties;
import com.sahilkalgutkar.trust.identity.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.identity.repo.AuditOutboxRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;

/**
 * Drains the audit outbox to Kafka.
 *
 * <p>Delivery is at-least-once and ordered per tenant: the tenant id is the partition key, so one
 * tenant's events land on one partition in the order they were written, which is what lets the
 * audit service chain them without sorting. A crash between the send and the {@code published_at}
 * update re-sends the row — the consumer dedupes on {@code eventId}, which is why that field is an
 * idempotency key rather than decoration.
 */
@Component
public class OutboxPublisher {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisher.class);

    private final AuditOutboxRepository outboxRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final IdentityProperties properties;
    private final Clock clock;

    public OutboxPublisher(AuditOutboxRepository outboxRepository,
                           KafkaTemplate<String, String> kafkaTemplate,
                           IdentityProperties properties,
                           Clock clock) {
        this.outboxRepository = outboxRepository;
        this.kafkaTemplate = kafkaTemplate;
        this.properties = properties;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${trust.identity.outbox-poll-interval-ms:1000}")
    @Transactional
    public void drain() {
        if (!properties.isAuditPublishingEnabled()) {
            return;
        }
        List<AuditOutboxEntity> pending = outboxRepository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc();
        for (AuditOutboxEntity entry : pending) {
            try {
                kafkaTemplate.send(AuditTopics.AUDIT_EVENTS, entry.getTenantId().toString(), entry.getPayload())
                        .get();
                entry.markPublished(clock.instant());
                outboxRepository.save(entry);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                // Leave it unpublished and stop: the next tick retries from the same point, which
                // preserves per-tenant ordering. Skipping ahead would not.
                log.warn("Audit outbox publish failed for {}; will retry", entry.getId(), e);
                return;
            }
        }
    }
}
