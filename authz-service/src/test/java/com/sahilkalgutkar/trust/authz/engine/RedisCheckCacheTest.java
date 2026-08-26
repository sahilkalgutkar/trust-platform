package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisCheckCacheTest {

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final AuthzProperties properties = new AuthzProperties();

    private RedisCheckCache cache;

    @BeforeEach
    void setUp() {
        when(redis.opsForValue()).thenReturn(values);
        cache = new RedisCheckCache(redis, properties);
    }

    @Test
    void anEntryIsStoredUnderItsRevisionWithTheConfiguredTtl() {
        properties.setCacheTtl(Duration.ofSeconds(45));

        cache.put("acme|document:readme#viewer@user:ada", 7, true);

        verify(values).set("authz:check:7:acme|document:readme#viewer@user:ada", "true",
                Duration.ofSeconds(45));
    }

    @Test
    void anEntryIsReadBackForTheSameRevision() {
        when(values.get("authz:check:7:key")).thenReturn("true");

        assertThat(cache.get("key", 7)).contains(true);
    }

    /** A write advances the revision, so every entry from before it is simply unreachable. */
    @Test
    void anEntryFromAnEarlierRevisionIsAMiss() {
        when(values.get("authz:check:7:key")).thenReturn("true");

        assertThat(cache.get("key", 8)).isEmpty();
    }

    @Test
    void anAbsentEntryIsAMiss() {
        when(values.get(anyString())).thenReturn(null);

        assertThat(cache.get("key", 1)).isEmpty();
    }

    /** A cache outage must cost latency, never correctness — misses, not errors. */
    @Test
    void aRedisFailureDegradesToAMissRatherThanPropagating() {
        when(values.get(anyString())).thenThrow(new IllegalStateException("connection refused"));

        assertThat(cache.get("key", 1)).isEmpty();
    }

    @Test
    void aRedisFailureOnWriteIsSwallowedBecauseTheAnswerIsStillCorrect() {
        org.mockito.Mockito.doThrow(new IllegalStateException("connection refused"))
                .when(values).set(anyString(), anyString(), any(Duration.class));

        cache.put("key", 1, true);
    }

    @Test
    void theCacheCanBeTurnedOffEntirely() {
        properties.setCacheEnabled(false);

        assertThat(cache.get("key", 1)).isEmpty();
        cache.put("key", 1, true);

        verify(values, never()).get(anyString());
        verify(values, never()).set(anyString(), anyString(), any(Duration.class));
    }
}
