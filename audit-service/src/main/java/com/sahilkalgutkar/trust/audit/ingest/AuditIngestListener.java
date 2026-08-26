package com.sahilkalgutkar.trust.audit.ingest;

import com.sahilkalgutkar.trust.audit.chain.AppendResult;
import com.sahilkalgutkar.trust.audit.chain.AuditChainService;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditTopics;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Consumes audit events from Kafka and extends the chain with them.
 *
 * <p>Concurrency is deliberately one thread per partition and the topic is keyed by tenant, so a
 * tenant's events arrive in the order they were produced and the chain is only ever extended from
 * one place. That is the whole reason ordering matters here — a hash chain has no way to insert a
 * record that shows up late.
 */
@Component
public class AuditIngestListener {

    private static final Logger log = LoggerFactory.getLogger(AuditIngestListener.class);

    private final AuditChainService chainService;

    public AuditIngestListener(AuditChainService chainService) {
        this.chainService = chainService;
    }

    @KafkaListener(topics = AuditTopics.AUDIT_EVENTS, groupId = "${trust.audit.consumer-group:audit-service}")
    public void onMessage(String payload) {
        AuditEvent event;
        try {
            event = CanonicalJson.parse(payload, AuditEvent.class);
            if (event == null) {
                // A literal `null` body parses without complaint and would otherwise reach the
                // chain service as a null event.
                throw new IllegalArgumentException("Message body was a JSON null");
            }
        } catch (IllegalArgumentException | NullPointerException malformed) {
            // Skipped rather than retried forever. A message this service cannot parse will not
            // become parseable on the next attempt, and blocking the partition on it would stop
            // auditing everything behind it — a far worse failure than one unrecorded event. The
            // ERROR log is the signal that something upstream is producing garbage.
            log.error("Unparseable audit message skipped; investigate the producer. payload={}",
                    truncate(payload), malformed);
            return;
        }

        try {
            AppendResult result = chainService.append(event);
            if (!result.appended()) {
                log.debug("Audit event {} was already in the chain; redelivery ignored", event.eventId());
            }
        } catch (RuntimeException e) {
            // Rethrown so Kafka redelivers: unlike a parse failure, a database problem is exactly
            // the kind that does resolve on retry, and dropping the event would leave a real gap.
            log.warn("Could not append audit event {}; it will be redelivered", event.eventId(), e);
            throw e;
        }
    }

    private static String truncate(String payload) {
        if (payload == null) {
            return "<null>";
        }
        return payload.length() <= 512 ? payload : payload.substring(0, 512) + "…";
    }
}
