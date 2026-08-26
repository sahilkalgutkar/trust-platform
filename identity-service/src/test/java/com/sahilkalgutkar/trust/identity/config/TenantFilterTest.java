package com.sahilkalgutkar.trust.identity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import com.sahilkalgutkar.trust.identity.domain.TenantEntity;
import com.sahilkalgutkar.trust.identity.repo.TenantRepository;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TenantFilterTest {

    private static final UUID TENANT_ID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private final TenantRepository repository = mock(TenantRepository.class);
    private final TenantFilter filter = new TenantFilter(repository, new ObjectMapper());

    private TenantEntity acme;

    @BeforeEach
    void setUp() {
        acme = new TenantEntity(TENANT_ID, "acme", "Acme Inc");
        when(repository.findBySlug(anyString())).thenReturn(Optional.empty());
        when(repository.findBySlug("acme")).thenReturn(Optional.of(acme));
    }

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    void theSlugIsTakenFromTheSecondPathSegment() {
        assertThat(TenantFilter.extractSlug("/t/acme/oauth2/token")).contains("acme");
        assertThat(TenantFilter.extractSlug("/t/acme")).contains("acme");
        assertThat(TenantFilter.extractSlug("/t/acme/")).contains("acme");
    }

    @Test
    void pathsOutsideTheTenantPrefixCarryNoSlug() {
        assertThat(TenantFilter.extractSlug("/actuator/health")).isEmpty();
        assertThat(TenantFilter.extractSlug("/admin/tenants")).isEmpty();
        assertThat(TenantFilter.extractSlug("/t/")).isEmpty();
        assertThat(TenantFilter.extractSlug(null)).isEmpty();
    }

    @Test
    void aKnownTenantIsBoundForTheDurationOfTheRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/acme/oauth2/jwks");
        request.setRequestURI("/t/acme/oauth2/jwks");
        AtomicReference<String> boundDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> boundDuringChain.set(TenantContext.require());

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(boundDuringChain.get()).isEqualTo(TENANT_ID.toString());
        assertThat(request.getAttribute("trust.tenant.slug")).isEqualTo("acme");
    }

    /** Request threads are pooled, so a tenant left bound would leak into the next request. */
    @Test
    void theTenantIsUnboundAfterTheRequest() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/acme/oauth2/jwks");
        request.setRequestURI("/t/acme/oauth2/jwks");

        filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> {
        });

        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void theTenantIsUnboundEvenWhenTheRequestBlowsUp() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/acme/oauth2/jwks");
        request.setRequestURI("/t/acme/oauth2/jwks");

        assertThatThrownBy(() -> filter.doFilter(request, new MockHttpServletResponse(),
                (req, res) -> {
                    throw new IllegalStateException("boom");
                })).hasMessage("boom");

        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void anUnknownTenantIsRejectedAndTheChainNeverRuns() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/ghost/oauth2/jwks");
        request.setRequestURI("/t/ghost/oauth2/jwks");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getContentAsString()).contains("Unknown or inactive tenant");
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void aSuspendedTenantIsTreatedAsUnknown() throws Exception {
        acme.setStatus("SUSPENDED");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/t/acme/oauth2/jwks");
        request.setRequestURI("/t/acme/oauth2/jwks");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, mock(FilterChain.class));

        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void requestsOutsideTheTenantPrefixPassThroughUnbound() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/actuator/health");
        request.setRequestURI("/actuator/health");
        AtomicReference<Boolean> ranWithoutTenant = new AtomicReference<>(false);

        filter.doFilter(request, new MockHttpServletResponse(),
                (req, res) -> ranWithoutTenant.set(TenantContext.current().isEmpty()));

        assertThat(ranWithoutTenant.get()).isTrue();
    }
}
