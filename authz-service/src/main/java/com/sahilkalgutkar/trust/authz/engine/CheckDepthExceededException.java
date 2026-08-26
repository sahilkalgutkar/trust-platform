package com.sahilkalgutkar.trust.authz.engine;

/** Thrown when a check recurses past the configured depth limit. */
public class CheckDepthExceededException extends RuntimeException {

    public CheckDepthExceededException(int maxDepth) {
        super("Check exceeded the maximum evaluation depth of " + maxDepth
                + " — the namespace may model an unbounded hierarchy");
    }
}
