package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.config.AuthzProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * The distributed check cache.
 *
 * <p>Every Redis call is wrapped: a cache that is down must degrade into extra database load, never
 * into failed authorization checks. A permission system that returns 500 when its cache blinks is
 * worse than one with no cache at all.
 */
@Component
public class RedisCheckCache implements CheckCache {

    private static final Logger log = LoggerFactory.getLogger(RedisCheckCache.class);

    private final StringRedisTemplate redis;
    private final AuthzProperties properties;

    public RedisCheckCache(StringRedisTemplate redis, AuthzProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    @Override
    public Optional<Boolean> get(String key, long revision) {
        if (!properties.isCacheEnabled()) {
            return Optional.empty();
        }
        try {
            String value = redis.opsForValue().get(redisKey(key, revision));
            return Optional.ofNullable(value).map(Boolean::valueOf);
        } catch (RuntimeException e) {
            log.warn("Check cache read failed; falling back to evaluation", e);
            return Optional.empty();
        }
    }

    @Override
    public void put(String key, long revision, boolean allowed) {
        if (!properties.isCacheEnabled()) {
            return;
        }
        try {
            redis.opsForValue().set(redisKey(key, revision), Boolean.toString(allowed),
                    properties.getCacheTtl());
        } catch (RuntimeException e) {
            log.warn("Check cache write failed; the answer is still correct, just not cached", e);
        }
    }

    private static String redisKey(String key, long revision) {
        return "authz:check:" + revision + ":" + key;
    }
}
