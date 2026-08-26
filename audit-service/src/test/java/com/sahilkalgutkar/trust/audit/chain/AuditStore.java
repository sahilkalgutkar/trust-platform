package com.sahilkalgutkar.trust.audit.chain;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import org.springframework.data.domain.Limit;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An in-memory stand-in for the audit table.
 *
 * <p>The repository is mocked over a real list rather than stubbed per call: these tests are about
 * what the chain looks like <em>after</em> a sequence of appends, and stubbing each read would mean
 * asserting against the answers the test itself supplied.
 */
final class AuditStore {

    private final List<AuditEventEntity> records = new ArrayList<>();

    AuditEventRepository repository() {
        AuditEventRepository repository = mock(AuditEventRepository.class);

        when(repository.findFirstByTenantIdOrderBySeqDesc(any())).thenAnswer(invocation ->
                records.stream()
                        .filter(r -> r.getTenantId().equals(invocation.<UUID>getArgument(0)))
                        .max(Comparator.comparingLong(AuditEventEntity::getSeq)));

        when(repository.existsByTenantIdAndEventId(any(), anyString())).thenAnswer(invocation ->
                records.stream()
                        .anyMatch(r -> r.getTenantId().equals(invocation.<UUID>getArgument(0))
                                && r.getEventId().equals(invocation.getArgument(1))));

        when(repository.findByTenantIdAndSeqGreaterThanOrderBySeqAsc(any(), anyLong(), any(Limit.class)))
                .thenAnswer(invocation -> records.stream()
                        .filter(r -> r.getTenantId().equals(invocation.<UUID>getArgument(0)))
                        .filter(r -> r.getSeq() > invocation.<Long>getArgument(1))
                        .sorted(Comparator.comparingLong(AuditEventEntity::getSeq))
                        .limit(invocation.<Limit>getArgument(2).max())
                        .toList());

        when(repository.findByTenantIdOrderBySeqDesc(any(), any(Limit.class)))
                .thenAnswer(invocation -> records.stream()
                        .filter(r -> r.getTenantId().equals(invocation.<UUID>getArgument(0)))
                        .sorted(Comparator.comparingLong(AuditEventEntity::getSeq).reversed())
                        .limit(invocation.<Limit>getArgument(1).max())
                        .toList());

        when(repository.countByTenantId(any())).thenAnswer(invocation -> records.stream()
                .filter(r -> r.getTenantId().equals(invocation.<UUID>getArgument(0)))
                .count());

        when(repository.save(any(AuditEventEntity.class))).thenAnswer(invocation -> {
            AuditEventEntity entity = invocation.getArgument(0);
            records.add(entity);
            return entity;
        });

        return repository;
    }

    List<AuditEventEntity> records() {
        return List.copyOf(records);
    }

    Optional<AuditEventEntity> at(UUID tenantId, long seq) {
        return records.stream()
                .filter(r -> r.getTenantId().equals(tenantId) && r.getSeq() == seq)
                .findFirst();
    }

    /** Replaces a stored record, standing in for someone with UPDATE on the table. */
    void tamper(UUID tenantId, long seq, AuditEventEntity replacement) {
        records.replaceAll(r -> r.getTenantId().equals(tenantId) && r.getSeq() == seq ? replacement : r);
    }

    void delete(UUID tenantId, long seq) {
        records.removeIf(r -> r.getTenantId().equals(tenantId) && r.getSeq() == seq);
    }
}
