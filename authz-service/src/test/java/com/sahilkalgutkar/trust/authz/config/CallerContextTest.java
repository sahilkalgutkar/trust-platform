package com.sahilkalgutkar.trust.authz.config;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CallerContextTest {

    private static final Caller CALLER =
            new Caller("user-1", UUID.randomUUID(), Set.of("authz.check"));

    @AfterEach
    void clear() {
        CallerContext.clear();
    }

    @Test
    void noCallerIsBoundUntilOneIsAuthenticated() {
        assertThat(CallerContext.current()).isEmpty();
        assertThatThrownBy(CallerContext::require)
                .isInstanceOf(CallerContext.NotAuthenticatedException.class);
    }

    @Test
    void theBoundCallerIsReturned() {
        CallerContext.set(CALLER);

        assertThat(CallerContext.require()).isEqualTo(CALLER);
        assertThat(CallerContext.current()).contains(CALLER);
    }

    @Test
    void aHeldScopePasses() {
        CallerContext.set(CALLER);

        assertThat(CallerContext.requireScope("authz.check")).isEqualTo(CALLER);
    }

    /** A valid token without the right scope is a 403, not a 401 — knowing who they are is settled. */
    @Test
    void aMissingScopeIsDistinctFromNotBeingAuthenticated() {
        CallerContext.set(CALLER);

        assertThatThrownBy(() -> CallerContext.requireScope("authz.write"))
                .isInstanceOf(CallerContext.InsufficientScopeException.class)
                .satisfies(e -> assertThat(((CallerContext.InsufficientScopeException) e).getRequired())
                        .isEqualTo("authz.write"));
    }

    @Test
    void clearingUnbindsTheCaller() {
        CallerContext.set(CALLER);
        CallerContext.clear();

        assertThat(CallerContext.current()).isEmpty();
    }
}
