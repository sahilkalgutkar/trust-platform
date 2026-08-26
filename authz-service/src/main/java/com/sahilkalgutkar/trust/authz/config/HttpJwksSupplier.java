package com.sahilkalgutkar.trust.authz.config;

import com.nimbusds.jose.jwk.JWKSet;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches each tenant's JWKS from the identity service, with a short cache.
 *
 * <p>The cache is what makes offline verification worth having: without it this service would make
 * an HTTP call to validate every request, which is exactly the coupling that verifying a signature
 * locally is supposed to remove. The TTL is the ceiling on how long a rotated-out key keeps being
 * accepted here, which is why the identity service keeps retired keys published for far longer than
 * this — the two windows have to overlap or rotation breaks traffic.
 */
@Component
public class HttpJwksSupplier implements JwksSupplier {

    private final RestClient restClient;
    private final AuthzProperties properties;
    private final Clock clock;
    private final Map<String, CachedKeySet> cache = new ConcurrentHashMap<>();

    public HttpJwksSupplier(RestClient.Builder restClientBuilder, AuthzProperties properties, Clock clock) {
        this.restClient = restClientBuilder.build();
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    public JWKSet forTenant(String tenantSlug) {
        CachedKeySet cached = cache.get(tenantSlug);
        Instant now = clock.instant();
        if (cached != null && cached.fetchedAt().plus(properties.getJwksCacheTtl()).isAfter(now)) {
            return cached.keySet();
        }
        JWKSet fetched = fetch(tenantSlug);
        cache.put(tenantSlug, new CachedKeySet(fetched, now));
        return fetched;
    }

    private JWKSet fetch(String tenantSlug) {
        String body = restClient.get()
                .uri(properties.jwksUriFor(tenantSlug))
                .retrieve()
                .body(String.class);
        try {
            return JWKSet.parse(body);
        } catch (ParseException e) {
            throw new IllegalStateException("Identity service returned an unparseable JWKS for tenant "
                    + tenantSlug, e);
        }
    }

    private record CachedKeySet(JWKSet keySet, Instant fetchedAt) {
    }
}
