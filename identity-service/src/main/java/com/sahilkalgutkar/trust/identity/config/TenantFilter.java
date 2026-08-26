package com.sahilkalgutkar.trust.identity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sahilkalgutkar.trust.common.error.ApiError;
import com.sahilkalgutkar.trust.common.error.OAuthErrors;
import com.sahilkalgutkar.trust.common.tenant.TenantContext;
import com.sahilkalgutkar.trust.identity.domain.TenantEntity;
import com.sahilkalgutkar.trust.identity.repo.TenantRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * Binds the tenant for the request from the {@code /t/{slug}/...} path prefix.
 *
 * <p>Putting the tenant in the path rather than a header is what makes the per-tenant issuer URL
 * ({@code /t/acme}) and the per-tenant discovery document work — a relying party configured for
 * tenant {@code acme} is pointed at URLs that cannot serve another tenant's metadata.
 *
 * <p>Unbinding in a {@code finally} is not optional: containers pool request threads, so a tenant
 * left bound is a tenant the next request inherits.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class TenantFilter extends OncePerRequestFilter {

    static final String TENANT_SLUG_ATTRIBUTE = "trust.tenant.slug";
    private static final String PREFIX = "/t/";

    private final TenantRepository tenantRepository;
    private final ObjectMapper objectMapper;

    public TenantFilter(TenantRepository tenantRepository, ObjectMapper objectMapper) {
        this.tenantRepository = tenantRepository;
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

        Optional<TenantEntity> tenant = tenantRepository.findBySlug(slug.get())
                .filter(TenantEntity::isActive);
        if (tenant.isEmpty()) {
            writeUnknownTenant(response);
            return;
        }

        TenantContext.set(tenant.get().getId().toString());
        request.setAttribute(TENANT_SLUG_ATTRIBUTE, tenant.get().getSlug());
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
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

    private void writeUnknownTenant(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                ApiError.of(OAuthErrors.INVALID_REQUEST, "Unknown or inactive tenant"));
    }
}
