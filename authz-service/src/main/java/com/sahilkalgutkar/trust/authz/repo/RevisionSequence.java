package com.sahilkalgutkar.trust.authz.repo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Hands out the monotonic revision numbers that back consistency tokens.
 *
 * <p>A database sequence rather than {@code max(revision) + 1}: the latter races two concurrent
 * writers into the same revision, which would let a caller hold a zookie that appears to include a
 * write it cannot actually see.
 */
@Component
public class RevisionSequence {

    private final JdbcTemplate jdbcTemplate;

    public RevisionSequence(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public long next() {
        Long value = jdbcTemplate.queryForObject("SELECT nextval('authz_revision')", Long.class);
        if (value == null) {
            throw new IllegalStateException("authz_revision sequence returned no value");
        }
        return value;
    }
}
