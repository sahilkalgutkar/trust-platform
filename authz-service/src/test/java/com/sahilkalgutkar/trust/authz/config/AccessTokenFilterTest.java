package com.sahilkalgutkar.trust.authz.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessTokenFilterTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final Caller CALLER = new Caller("user-1", TENANT, Set.of("authz.check"));

    private final AccessTokenVerifier verifier = mock(AccessTokenVerifier.class);
    private final AccessTokenFilter filter = new AccessTokenFilter(verifier, new ObjectMapper());

    @BeforeEach
    void setUp() {
        when(verifier.verify(anyString(), anyString())).thenReturn(Optional.empty());
        when(verifier.verify("good-token", "acme")).thenReturn(Optional.of(CALLER));
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
        CallerContext.clear();
    }

    @Test
    void theSlugIsTakenFromTheSecondPathSegment() {
        assertThat(AccessTokenFilter.extractSlug("/t/acme/v1/check")).contains("acme");
        assertThat(AccessTokenFilter.extractSlug("/t/acme")).contains("acme");
        assertThat(AccessTokenFilter.extractSlug("/actuator/health")).isEmpty();
        assertThat(AccessTokenFilter.extractSlug("/t/")).isEmpty();
        assertThat(AccessTokenFilter.extractSlug(null)).isEmpty();
    }

    @Test
    void theBearerSchemeIsMatchedCaseInsensitivelyAndTrimmed() {
        assertThat(AccessTokenFilter.bearerToken("Bearer  abc ")).contains("abc");
        assertThat(AccessTokenFilter.bearerToken("bearer abc")).contains("abc");
        assertThat(AccessTokenFilter.bearerToken("Basic abc")).isEmpty();
        assertThat(AccessTokenFilter.bearerToken("Bearer ")).isEmpty();
        assertThat(AccessTokenFilter.bearerToken(null)).isEmpty();
    }

    @Test
    void aValidTokenBindsBothTheCallerAndTheTenantItProves() throws Exception {
        AtomicReference<String> boundTenant = new AtomicReference<>();
        AtomicReference<Caller> boundCaller = new AtomicReference<>();

        filter.doFilter(request("/t/acme/v1/check", "Bearer good-token"), new MockHttpServletResponse(),
                (req, res) -> {
                    boundTenant.set(TenantContext.require());
                    boundCaller.set(CallerContext.require());
                });

        assertThat(boundTenant.get()).isEqualTo(TENANT.toString());
        assertThat(boundCaller.get()).isEqualTo(CALLER);
    }

    @Test
    void bothAreUnboundAfterTheRequest() throws Exception {
        filter.doFilter(request("/t/acme/v1/check", "Bearer good-token"), new MockHttpServletResponse(),
                (req, res) -> {
                });

        assertThat(TenantContext.current()).isEmpty();
        assertThat(CallerContext.current()).isEmpty();
    }

    @Test
    void bothAreUnboundEvenWhenTheRequestBlowsUp() {
        assertThatThrownBy(() -> filter.doFilter(request("/t/acme/v1/check", "Bearer good-token"),
                new MockHttpServletResponse(), (req, res) -> {
                    throw new IllegalStateException("boom");
                })).hasMessage("boom");

        assertThat(TenantContext.current()).isEmpty();
        assertThat(CallerContext.current()).isEmpty();
    }

    @Test
    void aMissingTokenIsA401WithAChallengeAndTheChainNeverRuns() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request("/t/acme/v1/check", null), response, chain);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).startsWith("Bearer");
        assertThat(response.getContentAsString()).contains("Bearer access token is required");
        verify(chain, never()).doFilter(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }

    @Test
    void anInvalidTokenIsA401() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request("/t/acme/v1/check", "Bearer forged"), response, mock(FilterChain.class));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("not valid for this tenant");
    }

    @Test
    void requestsOutsideTheTenantPrefixArentAuthenticatedAtAll() throws Exception {
        AtomicReference<Boolean> ranUnbound = new AtomicReference<>(false);

        filter.doFilter(request("/actuator/health", null), new MockHttpServletResponse(),
                (req, res) -> ranUnbound.set(CallerContext.current().isEmpty()));

        assertThat(ranUnbound.get()).isTrue();
    }

    private static MockHttpServletRequest request(String uri, String authorization) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
        request.setRequestURI(uri);
        if (authorization != null) {
            request.addHeader("Authorization", authorization);
        }
        return request;
    }
}
