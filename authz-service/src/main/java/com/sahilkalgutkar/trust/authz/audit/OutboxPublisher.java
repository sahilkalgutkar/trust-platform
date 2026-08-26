package com.sahilkalgutkar.trust.authz.audit;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import com.sahilkalgutkar.trust.authz.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.authz.repo.AuditOutboxRepository;
import com.sahilkalgutkar.trust.common.audit.AuditTopics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;

/** Drains the audit outbox to Kafka, keyed by tenant so one tenant's events stay ordered. */
@Component
public class OutboxPublisher {

    private static final Logger log = LoggerFactory.getLogger(OutboxPublisher.class);

    private final AuditOutboxRepository outboxRepository;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final AuthzProperties properties;
    private final Clock clock;

    public OutboxPublisher(AuditOutboxRepository outboxRepository,
                           KafkaTemplate<String, String> kafkaTemplate,
                           AuthzProperties properties, Clock clock) {
        this.outboxRepository = outboxRepository;
        this.kafkaTemplate = kafkaTemplate;
        this.properties = properties;
        this.clock = clock;
    }

    @Scheduled(fixedDelayString = "${trust.authz.outbox-poll-interval-ms:1000}")
    @Transactional
    public void drain() {
        if (!properties.isAuditPublishingEnabled()) {
            return;
        }
        List<AuditOutboxEntity> pending = outboxRepository.findTop200ByPublishedAtIsNullOrderByCreatedAtAsc();
        for (AuditOutboxEntity entry : pending) {
            try {
                kafkaTemplate.send(AuditTopics.AUDIT_EVENTS, entry.getTenantId().toString(),
                        entry.getPayload()).get();
                entry.markPublished(clock.instant());
                outboxRepository.save(entry);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                log.warn("Audit outbox publish failed for {}; will retry", entry.getId(), e);
                return;
            }
        }
    }
}
