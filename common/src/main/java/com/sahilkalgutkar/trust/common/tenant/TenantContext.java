package com.sahilkalgutkar.trust.common.tenant;

import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Holds the tenant the current thread is acting for.
 *
 * <p>Everything downstream — Hibernate's tenant discriminator, the audit writer, the authorization
 * cache key — reads the tenant from here rather than from a method argument. That is deliberate: a
 * tenant passed as an argument is a tenant a caller can forget to pass, and "forgot to pass the
 * tenant" is exactly the bug that turns into a cross-tenant data leak. Reading it from one place
 * means there is one place to get right, and one place to fail closed when it is missing.
 */
public final class TenantContext {

    private static final ThreadLocal<String> CURRENT = new ThreadLocal<>();

    private TenantContext() {
    }

    public static Optional<String> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    /**
     * @throws MissingTenantException if no tenant is bound — never a silent default, since a
     *                                default tenant would quietly widen every query it touched.
     */
    public static String require() {
        String tenant = CURRENT.get();
        if (tenant == null || tenant.isBlank()) {
            throw new MissingTenantException();
        }
        return tenant;
    }

    public static void set(String tenantId) {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        CURRENT.set(tenantId);
    }

    public static void clear() {
        CURRENT.remove();
    }

    /**
     * Runs {@code body} bound to {@code tenantId} and restores whatever was bound before — so a
     * nested call (a background refresh, an admin task acting for a tenant) cannot leave the
     * calling thread pointing at the wrong tenant when it returns.
     */
    public static <T> T callWith(String tenantId, Callable<T> body) throws Exception {
        String previous = CURRENT.get();
        set(tenantId);
        try {
            return body.call();
        } finally {
            if (previous == null) {
                CURRENT.remove();
            } else {
                CURRENT.set(previous);
            }
        }
    }

    public static void runWith(String tenantId, Runnable body) {
        try {
            callWith(tenantId, () -> {
                body.run();
                return null;
            });
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
