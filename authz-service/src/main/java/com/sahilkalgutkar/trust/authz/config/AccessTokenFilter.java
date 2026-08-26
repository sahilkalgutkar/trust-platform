package com.sahilkalgutkar.trust.authz.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.common.error.ApiError;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Authenticates every request under {@code /t/{tenant}/v1/} and binds the tenant it proves.
 *
 * <p>Unlike the identity service's filter, this one does not look the tenant up — it takes it from
 * the verified token. There is no tenants table in this service at all, which is the point: the
 * authorization service has no independent notion of who a tenant is, so it cannot disagree with
 * the identity service about it.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class AccessTokenFilter extends OncePerRequestFilter {

    private static final String PREFIX = "/t/";

    private final AccessTokenVerifier verifier;
    private final ObjectMapper objectMapper;

    public AccessTokenFilter(AccessTokenVerifier verifier, ObjectMapper objectMapper) {
        this.verifier = verifier;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        Optional<String> slug = extractSlug(request.getRequestURI());
        if (slug.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        Optional<String> token = bearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (token.isEmpty()) {
            unauthorized(response, "A Bearer access token is required");
            return;
        }

        Optional<Caller> caller = verifier.verify(token.get(), slug.get());
        if (caller.isEmpty()) {
            unauthorized(response, "The access token is not valid for this tenant");
            return;
        }

        CallerContext.set(caller.get());
        TenantContext.set(caller.get().tenantId().toString());
        try {
            chain.doFilter(request, response);
        } finally {
            // Request threads are pooled. Leaving either bound would hand the next request this
            // one's tenant, which is the whole class of bug this service exists to not have.
            TenantContext.clear();
            CallerContext.clear();
        }
    }

    static Optional<String> extractSlug(String uri) {
        if (uri == null || !uri.startsWith(PREFIX)) {
            return Optional.empty();
        }
        String rest = uri.substring(PREFIX.length());
        int slash = rest.indexOf('/');
        String slug = slash < 0 ? rest : rest.substring(0, slash);
        return slug.isBlank() ? Optional.empty() : Optional.of(slug);
    }

    static Optional<String> bearerToken(String authorization) {
        return Optional.ofNullable(authorization)
                .filter(header -> header.regionMatches(true, 0, "Bearer ", 0, 7))
                .map(header -> header.substring(7).trim())
                .filter(token -> !token.isEmpty());
    }

    private void unauthorized(HttpServletResponse response, String description) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"trust-platform\"");
        objectMapper.writeValue(response.getOutputStream(), ApiError.of("invalid_token", description));
    }
}
