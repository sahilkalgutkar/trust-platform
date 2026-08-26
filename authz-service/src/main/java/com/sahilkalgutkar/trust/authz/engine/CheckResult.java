package com.sahilkalgutkar.trust.authz.engine;

/**
 * The answer to one permission question, plus enough to reason about how it was reached.
 *
 * @param revision   the storage revision this answer reflects, returned as a zookie so the caller
 *                   can require at least this freshness next time
 * @param tuplesRead how many tuples the evaluation touched — the number that tells you whether a
 *                   namespace is modelled well or is about to become an outage
 */
public record CheckResult(boolean allowed, long revision, boolean fromCache, int tuplesRead, int maxDepthReached) {

    public static CheckResult cached(boolean allowed, long revision) {
        return new CheckResult(allowed, revision, true, 0, 0);
    }
}
