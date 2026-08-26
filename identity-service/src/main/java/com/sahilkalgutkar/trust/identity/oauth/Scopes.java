package com.sahilkalgutkar.trust.identity.oauth;

import com.sahilkalgutkar.trust.common.error.OAuthErrors;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

/** Space-delimited scope parsing, with downscoping rules. */
public final class Scopes {

    private Scopes() {
    }

    public static Set<String> parse(String spaceDelimited) {
        if (spaceDelimited == null || spaceDelimited.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(spaceDelimited.trim().split("\\s+"))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String join(Set<String> scopes) {
        return String.join(" ", scopes);
    }

    /**
     * Resolves the scope for a new grant. An omitted request means "everything registered"; an
     * explicit request must be a subset. Silently trimming an over-broad request to what is allowed
     * would leave the client believing it holds a scope it does not, so it is an error instead.
     */
    public static String resolveRequested(String requested, Set<String> registered) {
        Set<String> asked = parse(requested);
        if (asked.isEmpty()) {
            return join(registered);
        }
        if (!registered.containsAll(asked)) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_SCOPE,
                    "Requested scope exceeds what this client is registered for");
        }
        return join(asked);
    }

    /**
     * Resolves the scope when refreshing. RFC 6749 §6 allows narrowing but never widening — a
     * refresh token is not a way to gain scopes the original grant did not carry.
     */
    public static String resolveRefreshed(String requested, String granted) {
        Set<String> asked = parse(requested);
        Set<String> original = parse(granted);
        if (asked.isEmpty()) {
            return granted;
        }
        if (!original.containsAll(asked)) {
            throw OAuthException.badRequest(OAuthErrors.INVALID_SCOPE,
                    "A refresh may narrow the granted scope but never widen it");
        }
        return join(asked);
    }
}
