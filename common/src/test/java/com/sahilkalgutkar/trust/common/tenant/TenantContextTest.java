package com.sahilkalgutkar.trust.common.tenant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantContextTest {

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    @Test
    void currentIsEmptyUntilATenantIsBound() {
        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void requireFailsClosedRatherThanDefaulting() {
        assertThatThrownBy(TenantContext::require)
                .isInstanceOf(MissingTenantException.class)
                .hasMessageContaining("No tenant bound");
    }

    @Test
    void setThenRequireReturnsTheBoundTenant() {
        TenantContext.set("acme");

        assertThat(TenantContext.require()).isEqualTo("acme");
        assertThat(TenantContext.current()).contains("acme");
    }

    @Test
    void blankTenantIsRejectedAtTheBoundary() {
        assertThatThrownBy(() -> TenantContext.set("  "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> TenantContext.set(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void clearUnbindsTheTenant() {
        TenantContext.set("acme");
        TenantContext.clear();

        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void callWithRestoresThePreviousTenant() throws Exception {
        TenantContext.set("outer");

        String seen = TenantContext.callWith("inner", TenantContext::require);

        assertThat(seen).isEqualTo("inner");
        assertThat(TenantContext.require()).isEqualTo("outer");
    }

    @Test
    void callWithLeavesTheThreadUnboundWhenItStartedUnbound() throws Exception {
        TenantContext.callWith("inner", TenantContext::require);

        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void callWithRestoresEvenWhenTheBodyThrows() {
        TenantContext.set("outer");

        assertThatThrownBy(() -> TenantContext.callWith("inner", () -> {
            throw new IllegalStateException("boom");
        })).hasMessage("boom");

        assertThat(TenantContext.require()).isEqualTo("outer");
    }

    @Test
    void runWithPropagatesRuntimeExceptionsUnwrapped() {
        assertThatThrownBy(() -> TenantContext.runWith("acme", () -> {
            throw new IllegalArgumentException("bad input");
        }))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("bad input");
    }

    @Test
    void runWithBindsTheTenantForTheBody() {
        StringBuilder seen = new StringBuilder();

        TenantContext.runWith("acme", () -> seen.append(TenantContext.require()));

        assertThat(seen).hasToString("acme");
        assertThat(TenantContext.current()).isEmpty();
    }

    @Test
    void aTenantBoundOnOneThreadIsInvisibleToAnother() throws Exception {
        TenantContext.set("acme");
        Optional<String> seenOnOtherThread = runOnNewThread(TenantContext::current);

        assertThat(seenOnOtherThread).isEmpty();
    }

    private static Optional<String> runOnNewThread(java.util.function.Supplier<Optional<String>> body)
            throws InterruptedException {
        var result = new java.util.concurrent.atomic.AtomicReference<Optional<String>>(Optional.empty());
        Thread thread = new Thread(() -> result.set(body.get()));
        thread.start();
        thread.join();
        return result.get();
    }
}
