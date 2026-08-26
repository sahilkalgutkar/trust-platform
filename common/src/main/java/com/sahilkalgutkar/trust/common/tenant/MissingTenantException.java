package com.sahilkalgutkar.trust.common.tenant;

/** Thrown when work that touches tenant-scoped data runs with no tenant bound to the thread. */
public class MissingTenantException extends IllegalStateException {

    public MissingTenantException() {
        super("No tenant bound to the current context");
    }
}
