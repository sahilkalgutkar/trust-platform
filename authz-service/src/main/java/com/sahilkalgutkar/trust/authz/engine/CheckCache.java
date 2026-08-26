package com.sahilkalgutkar.trust.authz.engine;

import java.util.Optional;

/**
 * Caches check results, keyed by the storage revision they were computed at.
 *
 * <p>Putting the revision in the key is what makes this safe rather than merely fast: any write
 * advances the revision, so every entry from before that write becomes unreachable at once. It is
 * far more coarse than Zanzibar, which invalidates precisely the checks a changed tuple could
 * affect — but coarse-and-correct beats precise-and-subtly-wrong for a permission cache, and the
 * cost is a burst of misses after each write rather than a stale allow.
 */
public interface CheckCache {

    /** @return the cached answer, or empty when nothing was computed at or after {@code revision} */
    Optional<Boolean> get(String key, long revision);

    void put(String key, long revision, boolean allowed);
}
