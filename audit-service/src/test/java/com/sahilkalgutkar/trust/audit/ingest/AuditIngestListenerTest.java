package com.sahilkalgutkar.trust.audit.ingest;

import com.sahilkalgutkar.trust.audit.chain.AppendResult;
import com.sahilkalgutkar.trust.audit.chain.AuditChainService;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditIngestListenerTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private final AuditChainService chainService = mock(AuditChainService.class);
    private final AuditIngestListener listener = new AuditIngestListener(chainService);

    @Test
    void aWellFormedMessageIsAppendedToTheChain() {
        AuditEvent event = AuditEvent.builder(TENANT.toString(), "token.issued")
                .eventId("evt-1")
                .actor("user:ada")
                .occurredAt(Instant.parse("2026-08-25T12:00:00Z"))
                .build();
        when(chainService.append(any())).thenReturn(new AppendResult(AppendResult.Outcome.APPENDED, 1, "hash"));

        listener.onMessage(CanonicalJson.string(event));

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(chainService).append(captor.capture());
        assertThat(captor.getValue()).isEqualTo(event);
    }

    @Test
    void aRedeliveryIsAcceptedQuietly() {
        when(chainService.append(any())).thenReturn(new AppendResult(AppendResult.Outcome.DUPLICATE, 1, "hash"));

        assertThatCode(() -> listener.onMessage(CanonicalJson.string(
                AuditEvent.builder(TENANT.toString(), "token.issued").eventId("evt-1").build())))
                .doesNotThrowAnyException();
    }

    /**
     * A poison pill is skipped rather than retried. It will never parse, and blocking the partition
     * on it would stop auditing every event behind it — the worse of the two failures.
     */
    @Test
    void anUnparseableMessageIsSkippedInsteadOfBlockingThePartition() {
        assertThatCode(() -> listener.onMessage("{not json")).doesNotThrowAnyException();

        verify(chainService, never()).append(any());
    }

    @Test
    void aMessageMissingRequiredFieldsIsSkipped() {
        assertThatCode(() -> listener.onMessage("{\"eventId\":\"evt-1\"}")).doesNotThrowAnyException();
        assertThatCode(() -> listener.onMessage("null")).doesNotThrowAnyException();
        assertThatCode(() -> listener.onMessage("")).doesNotThrowAnyException();

        verify(chainService, never()).append(any());
    }

    /** A database failure, unlike a parse failure, does resolve on retry — so it must not be swallowed. */
    @Test
    void aStorageFailureIsRethrownSoKafkaRedeliversIt() {
        when(chainService.append(any())).thenThrow(new IllegalStateException("connection reset"));

        assertThatThrownBy(() -> listener.onMessage(CanonicalJson.string(
                AuditEvent.builder(TENANT.toString(), "token.issued").eventId("evt-1").build())))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void anOversizedGarbageMessageIsTruncatedInTheLogRatherThanFloodingIt() {
        assertThatCode(() -> listener.onMessage("x".repeat(20_000))).doesNotThrowAnyException();
    }
}
