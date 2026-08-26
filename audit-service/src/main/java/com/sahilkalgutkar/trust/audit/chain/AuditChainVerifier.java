package com.sahilkalgutkar.trust.audit.chain;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import com.sahilkalgutkar.trust.common.hash.HashChain;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

/**
 * Walks a tenant's chain and reports the first place it stops making sense.
 *
 * <p>Four things are checked at each link, and each one catches a different way of interfering with
 * the record:
 *
 * <ol>
 *   <li><b>The sequence has no gaps.</b> Deleting a row outright leaves a hole that the hashes alone
 *       would not notice, because the surviving records still chain to each other.</li>
 *   <li><b>{@code prev_hash} matches the previous record's hash.</b> Splicing a record in or out of
 *       the middle breaks this immediately.</li>
 *   <li><b>{@code hash} is what the payload and {@code prev_hash} actually produce.</b> Editing the
 *       payload — the authoritative copy of the event — breaks this.</li>
 *   <li><b>The indexed columns still agree with the payload.</b> Without this, someone could quietly
 *       rewrite the {@code actor} column, leaving the chain intact while every query and export
 *       reported the wrong person.</li>
 * </ol>
 *
 * <p>It reads in pages rather than loading the tenant's history into memory, because the one time
 * anybody runs this is on a log that has been accumulating for years.
 */
@Service
public class AuditChainVerifier {

    private static final int PAGE_SIZE = 500;

    private final AuditEventRepository repository;

    public AuditChainVerifier(AuditEventRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public ChainVerification verify(UUID tenantId) {
        String expectedPrevHash = HashChain.GENESIS;
        long expectedSeq = 1;
        long checked = 0;
        String lastHash = HashChain.GENESIS;

        while (true) {
            List<AuditEventEntity> page = repository.findByTenantIdAndSeqGreaterThanOrderBySeqAsc(
                    tenantId, expectedSeq - 1, Limit.of(PAGE_SIZE));
            if (page.isEmpty()) {
                return ChainVerification.intact(checked, lastHash);
            }

            for (AuditEventEntity record : page) {
                if (record.getSeq() != expectedSeq) {
                    return ChainVerification.broken(checked, expectedSeq,
                            "Missing record at position " + expectedSeq + "; the next stored record is "
                                    + record.getSeq());
                }
                if (!record.getPrevHash().equalsIgnoreCase(expectedPrevHash)) {
                    return ChainVerification.broken(checked, record.getSeq(),
                            "Record does not chain to its predecessor");
                }
                String recomputed = HashChain.link(record.getPrevHash(),
                        record.getPayload().getBytes(StandardCharsets.UTF_8));
                if (!recomputed.equalsIgnoreCase(record.getHash())) {
                    return ChainVerification.broken(checked, record.getSeq(),
                            "Stored hash does not match the record's contents");
                }
                if (!columnsAgreeWithPayload(record)) {
                    return ChainVerification.broken(checked, record.getSeq(),
                            "Indexed columns disagree with the signed payload");
                }

                expectedPrevHash = record.getHash();
                lastHash = record.getHash();
                expectedSeq++;
                checked++;
            }

            if (page.size() < PAGE_SIZE) {
                return ChainVerification.intact(checked, lastHash);
            }
        }
    }

    private static boolean columnsAgreeWithPayload(AuditEventEntity record) {
        AuditEvent event;
        try {
            event = CanonicalJson.parse(record.getPayload(), AuditEvent.class);
        } catch (IllegalArgumentException unparseable) {
            return false;
        }
        return event.eventId().equals(record.getEventId())
                && event.actor().equals(record.getActor())
                && event.action().equals(record.getAction())
                && event.outcome() == record.getOutcome()
                && event.occurredAt().equals(record.getOccurredAt())
                && java.util.Objects.equals(event.resourceType(), record.getResourceType())
                && java.util.Objects.equals(event.resourceId(), record.getResourceId());
    }
}
