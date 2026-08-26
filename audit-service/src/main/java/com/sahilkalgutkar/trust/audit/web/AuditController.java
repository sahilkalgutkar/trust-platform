package com.sahilkalgutkar.trust.audit.web;

import com.sahilkalgutkar.trust.audit.chain.AuditChainService;
import com.sahilkalgutkar.trust.audit.chain.AuditChainVerifier;
import com.sahilkalgutkar.trust.audit.chain.ChainHead;
import com.sahilkalgutkar.trust.audit.chain.ChainVerification;
import com.sahilkalgutkar.trust.audit.config.AuditProperties;
import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import org.springframework.data.domain.Limit;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The operator-facing read API. Nothing here writes: the only way into the log is through Kafka.
 */
@RestController
public class AuditController {

    private static final String ADMIN_KEY_HEADER = "X-Admin-Key";

    private final AuditEventRepository repository;
    private final AuditChainService chainService;
    private final AuditChainVerifier verifier;
    private final AuditProperties properties;
    private final AdminGuard adminGuard;

    public AuditController(AuditEventRepository repository, AuditChainService chainService,
                           AuditChainVerifier verifier, AuditProperties properties,
                           AdminGuard adminGuard) {
        this.repository = repository;
        this.chainService = chainService;
        this.verifier = verifier;
        this.properties = properties;
        this.adminGuard = adminGuard;
    }

    /** The tip of the chain — the value to record somewhere outside this database. */
    @GetMapping("/admin/tenants/{tenantId}/audit/head")
    public ChainHead head(@PathVariable("tenantId") UUID tenantId,
                          @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey) {
        adminGuard.require(adminKey);
        return chainService.head(tenantId);
    }

    @GetMapping("/admin/tenants/{tenantId}/audit/events")
    public List<AuditRecord> events(@PathVariable("tenantId") UUID tenantId,
                                    @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey,
                                    @RequestParam(value = "limit", defaultValue = "50") int limit) {
        adminGuard.require(adminKey);
        int capped = Math.clamp(limit, 1, properties.getMaxPageSize());
        return repository.findByTenantIdOrderBySeqDesc(tenantId, Limit.of(capped)).stream()
                .map(AuditRecord::from)
                .toList();
    }

    /**
     * Walks the whole chain. A POST rather than a GET because on a long-lived log this is expensive
     * enough that nobody should trigger it by prefetching a link.
     */
    @PostMapping("/admin/tenants/{tenantId}/audit/verify")
    public ChainVerification verify(@PathVariable("tenantId") UUID tenantId,
                                    @RequestHeader(value = ADMIN_KEY_HEADER, required = false) String adminKey) {
        adminGuard.require(adminKey);
        return verifier.verify(tenantId);
    }

    /** The read model. Includes the hashes, so a reader can spot-check a record without trusting us. */
    public record AuditRecord(long seq, String eventId, String actor, String action, String resourceType,
                              String resourceId, String outcome, Instant occurredAt, String prevHash,
                              String hash) {

        static AuditRecord from(AuditEventEntity entity) {
            return new AuditRecord(entity.getSeq(), entity.getEventId(), entity.getActor(),
                    entity.getAction(), entity.getResourceType(), entity.getResourceId(),
                    entity.getOutcome().name(), entity.getOccurredAt(), entity.getPrevHash(),
                    entity.getHash());
        }
    }
}
