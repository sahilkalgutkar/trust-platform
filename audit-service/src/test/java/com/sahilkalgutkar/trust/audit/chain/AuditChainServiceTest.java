package com.sahilkalgutkar.trust.audit.chain;

import com.sahilkalgutkar.trust.audit.domain.AuditEventEntity;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import com.sahilkalgutkar.trust.common.audit.AuditEvent;
import com.sahilkalgutkar.trust.common.audit.AuditOutcome;
import com.sahilkalgutkar.trust.common.hash.CanonicalJson;
import com.sahilkalgutkar.trust.common.hash.HashChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AuditChainServiceTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID OTHER_TENANT = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final Instant NOW = Instant.parse("2026-08-25T12:00:00Z");

    private AuditStore store;
    private AuditChainService service;

    @BeforeEach
    void setUp() {
        store = new AuditStore();
        AuditEventRepository repository = store.repository();
        service = new AuditChainService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void theFirstRecordChainsFromGenesis() {
        AppendResult result = service.append(event(TENANT, "evt-1", "token.issued"));

        assertThat(result.appended()).isTrue();
        assertThat(result.seq()).isEqualTo(1);

        AuditEventEntity stored = store.at(TENANT, 1).orElseThrow();
        assertThat(stored.getPrevHash()).isEqualTo(HashChain.GENESIS);
        assertThat(stored.getHash()).isEqualTo(result.hash()).matches("[0-9a-f]{64}");
    }

    @Test
    void eachRecordChainsFromTheOneBeforeIt() {
        service.append(event(TENANT, "evt-1", "token.issued"));
        AppendResult second = service.append(event(TENANT, "evt-2", "token.refreshed"));

        assertThat(second.seq()).isEqualTo(2);
        assertThat(store.at(TENANT, 2).orElseThrow().getPrevHash())
                .isEqualTo(store.at(TENANT, 1).orElseThrow().getHash());
    }

    @Test
    void theStoredPayloadIsExactlyWhatWasHashed() {
        AuditEvent event = event(TENANT, "evt-1", "token.issued");

        service.append(event);

        AuditEventEntity stored = store.at(TENANT, 1).orElseThrow();
        assertThat(stored.getPayload()).isEqualTo(CanonicalJson.string(event));
        assertThat(HashChain.link(stored.getPrevHash(),
                stored.getPayload().getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                .isEqualTo(stored.getHash());
    }

    @Test
    void theIndexedColumnsMirrorThePayload() {
        service.append(AuditEvent.builder(TENANT.toString(), "refresh.reuse_detected")
                .eventId("evt-1")
                .actor("client:web-app")
                .resource("refresh_family", "fam-1")
                .outcome(AuditOutcome.DENIED)
                .occurredAt(NOW)
                .build());

        AuditEventEntity stored = store.at(TENANT, 1).orElseThrow();
        assertThat(stored.getActor()).isEqualTo("client:web-app");
        assertThat(stored.getAction()).isEqualTo("refresh.reuse_detected");
        assertThat(stored.getResourceType()).isEqualTo("refresh_family");
        assertThat(stored.getResourceId()).isEqualTo("fam-1");
        assertThat(stored.getOutcome()).isEqualTo(AuditOutcome.DENIED);
        assertThat(stored.getOccurredAt()).isEqualTo(NOW);
        assertThat(stored.getRecordedAt()).isEqualTo(NOW);
    }

    /** Kafka redelivery must not put a second copy of one event into the record. */
    @Test
    void redeliveringAnEventIsIgnoredRatherThanAppendedTwice() {
        AuditEvent event = event(TENANT, "evt-1", "token.issued");
        service.append(event);

        AppendResult redelivered = service.append(event);

        assertThat(redelivered.appended()).isFalse();
        assertThat(redelivered.outcome()).isEqualTo(AppendResult.Outcome.DUPLICATE);
        assertThat(store.records()).hasSize(1);
    }

    @Test
    void aRedeliveryReportsTheChainAsItStands() {
        service.append(event(TENANT, "evt-1", "token.issued"));
        service.append(event(TENANT, "evt-2", "token.refreshed"));

        AppendResult redelivered = service.append(event(TENANT, "evt-1", "token.issued"));

        assertThat(redelivered.seq()).isEqualTo(2);
        assertThat(redelivered.hash()).isEqualTo(store.at(TENANT, 2).orElseThrow().getHash());
    }

    /** Each tenant gets its own chain — one tenant's volume cannot shift another's positions. */
    @Test
    void tenantsHaveIndependentChains() {
        service.append(event(TENANT, "evt-1", "token.issued"));
        service.append(event(TENANT, "evt-2", "token.refreshed"));

        AppendResult otherTenant = service.append(event(OTHER_TENANT, "evt-3", "token.issued"));

        assertThat(otherTenant.seq()).isEqualTo(1);
        assertThat(store.at(OTHER_TENANT, 1).orElseThrow().getPrevHash()).isEqualTo(HashChain.GENESIS);
    }

    @Test
    void theSameEventIdInTwoTenantsIsTwoDifferentEvents() {
        service.append(event(TENANT, "shared-id", "token.issued"));

        AppendResult other = service.append(event(OTHER_TENANT, "shared-id", "token.issued"));

        assertThat(other.appended()).isTrue();
    }

    @Test
    void identicalEventsInDifferentPositionsHashDifferently() {
        service.append(event(TENANT, "evt-1", "token.issued"));
        service.append(event(TENANT, "evt-2", "token.issued"));

        assertThat(store.at(TENANT, 1).orElseThrow().getHash())
                .isNotEqualTo(store.at(TENANT, 2).orElseThrow().getHash());
    }

    @Test
    void anEmptyChainReportsTheGenesisHead() {
        ChainHead head = service.head(TENANT);

        assertThat(head.seq()).isZero();
        assertThat(head.hash()).isEqualTo(HashChain.GENESIS);
        assertThat(head.recordedAt()).isNull();
    }

    @Test
    void theHeadTracksTheMostRecentRecord() {
        service.append(event(TENANT, "evt-1", "token.issued"));
        AppendResult second = service.append(event(TENANT, "evt-2", "token.refreshed"));

        ChainHead head = service.head(TENANT);

        assertThat(head.seq()).isEqualTo(2);
        assertThat(head.hash()).isEqualTo(second.hash());
        assertThat(head.recordedAt()).isEqualTo(NOW);
    }

    private static AuditEvent event(UUID tenant, String eventId, String action) {
        return AuditEvent.builder(tenant.toString(), action)
                .eventId(eventId)
                .actor("user:ada")
                .occurredAt(NOW)
                .build();
    }
}
