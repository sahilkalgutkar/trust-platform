package com.sahilkalgutkar.trust.authz.config;

import java.util.Optional;

/** Holds the authenticated caller for the current request thread. */
public final class CallerContext {

    private static final ThreadLocal<Caller> CURRENT = new ThreadLocal<>();

    private CallerContext() {
    }

    public static Optional<Caller> current() {
        return Optional.ofNullable(CURRENT.get());
    }

    public static Caller require() {
        Caller caller = CURRENT.get();
        if (caller == null) {
            throw new NotAuthenticatedException("No authenticated caller on this request");
        }
        return caller;
    }

    /**
     * @throws InsufficientScopeException when the token is valid but does not carry the scope this
     *                                    operation needs — a 403, distinct from the 401 that means
     *                                    "who are you"
     */
    public static Caller requireScope(String scope) {
        Caller caller = require();
        if (!caller.hasScope(scope)) {
            throw new InsufficientScopeException(scope);
        }
        return caller;
    }

    public static void set(Caller caller) {
        CURRENT.set(caller);
    }

    public static void clear() {
        CURRENT.remove();
    }

    public static class NotAuthenticatedException extends RuntimeException {
        public NotAuthenticatedException(String message) {
            super(message);
        }
    }

    public static class InsufficientScopeException extends RuntimeException {
        private final String required;

        public InsufficientScopeException(String required) {
            super("This operation requires the " + required + " scope");
            this.required = required;
        }

        public String getRequired() {
            return required;
        }
    }
}
