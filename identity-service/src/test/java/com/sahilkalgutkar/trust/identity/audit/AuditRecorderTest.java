package com.sahilkalgutkar.trust.identity.audit;

import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import com.sahilkalgutkar.trust.identity.domain.AuditOutboxEntity;
import com.sahilkalgutkar.trust.identity.repo.AuditOutboxRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditRecorderTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private final AuditOutboxRepository repository = mock(AuditOutboxRepository.class);
    private final AuditRecorder recorder = new AuditRecorder(repository);

    @Test
    void anEventIsWrittenToTheOutboxAsCanonicalJson() {
        AuditEvent event = AuditEvent.builder(TENANT.toString(), "token.issued")
                .actor("user:42")
                .outcome(AuditOutcome.SUCCESS)
                .attribute("scope", "openid")
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .build();

        recorder.record(event);

        ArgumentCaptor<AuditOutboxEntity> captor = ArgumentCaptor.forClass(AuditOutboxEntity.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getTenantId()).isEqualTo(TENANT);
        assertThat(captor.getValue().getPayload())
                .contains("\"action\":\"token.issued\"")
                .contains("\"actor\":\"user:42\"")
                .contains("\"occurredAt\":\"2026-08-25T12:00:00Z\"");
        assertThat(captor.getValue().getPublishedAt()).isNull();
    }

    @Test
    void everyEntryGetsItsOwnIdSoRedeliveryCanBeDeduped() {
        AuditEvent event = AuditEvent.builder(TENANT.toString(), "token.issued").build();

        recorder.record(event);
        recorder.record(event);

        ArgumentCaptor<AuditOutboxEntity> captor = ArgumentCaptor.forClass(AuditOutboxEntity.class);
        verify(repository, org.mockito.Mockito.times(2)).save(captor.capture());
        assertThat(captor.getAllValues().get(0).getId())
                .isNotEqualTo(captor.getAllValues().get(1).getId());
    }
}
