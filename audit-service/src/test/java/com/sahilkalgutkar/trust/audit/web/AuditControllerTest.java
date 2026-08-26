package com.sahilkalgutkar.trust.audit.web;

import com.sahilkalgutkar.trust.audit.chain.AuditChainService;
import com.sahilkalgutkar.trust.audit.chain.AuditChainVerifier;
import com.sahilkalgutkar.trust.audit.chain.ChainHead;
import com.sahilkalgutkar.trust.audit.chain.ChainVerification;
import com.sahilkalgutkar.trust.audit.config.AuditProperties;
import com.sahilkalgutkar.trust.audit.repo.AuditEventRepository;
import com.sahilkalgutkar.trust.common.error.ApiError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Limit;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuditControllerTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final String KEY = "test-admin-key";

    private final AuditEventRepository repository = mock(AuditEventRepository.class);
    private final AuditChainService chainService = mock(AuditChainService.class);
    private final AuditChainVerifier verifier = mock(AuditChainVerifier.class);
    private final AuditProperties properties = new AuditProperties();

    private AuditController controller;

    @BeforeEach
    void setUp() {
        properties.setAdminApiKey(KEY);
        controller = new AuditController(repository, chainService, verifier, properties,
                new AdminGuard(properties));
        when(repository.findByTenantIdOrderBySeqDesc(any(), any(Limit.class))).thenReturn(List.of());
    }

    @Test
    void everyEndpointRequiresTheAdminKey() {
        assertThatThrownBy(() -> controller.head(TENANT, "wrong"))
                .isInstanceOf(AdminGuard.NotAuthorizedException.class);
        assertThatThrownBy(() -> controller.events(TENANT, null, 10))
                .isInstanceOf(AdminGuard.NotAuthorizedException.class);
        assertThatThrownBy(() -> controller.verify(TENANT, ""))
                .isInstanceOf(AdminGuard.NotAuthorizedException.class);
    }

    @Test
    void theRightKeyGetsThrough() {
        when(chainService.head(TENANT)).thenReturn(new ChainHead(3, "abc", null));

        assertThat(controller.head(TENANT, KEY).seq()).isEqualTo(3);
    }

    /** An unbounded limit is a denial-of-service waiting to be discovered by a curious operator. */
    @Test
    void theRequestedLimitIsCappedAtTheConfiguredMaximum() {
        properties.setMaxPageSize(100);

        controller.events(TENANT, KEY, 10_000);

        ArgumentCaptor<Limit> limit = ArgumentCaptor.forClass(Limit.class);
        verify(repository).findByTenantIdOrderBySeqDesc(any(), limit.capture());
        assertThat(limit.getValue().max()).isEqualTo(100);
    }

    @Test
    void aNonsensicalLimitIsRaisedToOneRatherThanRejected() {
        controller.events(TENANT, KEY, -5);

        ArgumentCaptor<Limit> limit = ArgumentCaptor.forClass(Limit.class);
        verify(repository).findByTenantIdOrderBySeqDesc(any(), limit.capture());
        assertThat(limit.getValue().max()).isEqualTo(1);
    }

    @Test
    void verificationIsDelegatedToTheVerifier() {
        when(verifier.verify(TENANT)).thenReturn(ChainVerification.broken(4, 5, "tampered"));

        ChainVerification result = controller.verify(TENANT, KEY);

        assertThat(result.intact()).isFalse();
        assertThat(result.brokenAtSeq()).isEqualTo(5);
    }

    @Test
    void anUnauthorizedCallBecomesA401() {
        ResponseEntity<ApiError> response = new AuditExceptionHandler()
                .handleUnauthorized(new AdminGuard.NotAuthorizedException());

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().error()).isEqualTo("access_denied");
    }

    @Test
    void aBadRequestBecomesA400() {
        ResponseEntity<ApiError> response = new AuditExceptionHandler()
                .handleBadRequest(new IllegalArgumentException("not a uuid"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().errorDescription()).isEqualTo("not a uuid");
    }

    @Test
    void aKeyThatIsAPrefixOfTheRealOneIsRejected() {
        assertThatThrownBy(() -> controller.head(TENANT, "test-admin"))
                .isInstanceOf(AdminGuard.NotAuthorizedException.class);
        assertThatCode(() -> controller.head(TENANT, KEY)).doesNotThrowAnyException();
    }
}
