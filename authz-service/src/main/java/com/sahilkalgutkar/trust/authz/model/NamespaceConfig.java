package com.sahilkalgutkar.trust.authz.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One namespace's relations and how each is derived.
 *
 * <p>A relation with no rewrite defaults to {@link Rewrite.This} — direct tuples only — which keeps
 * the simple case ({@code owner}) free of ceremony while leaving the derived ones explicit.
 */
public record NamespaceConfig(String name, Map<String, Rewrite> relations) {

    public NamespaceConfig {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Namespace name is required");
        }
        relations = relations == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(relations));
    }

    public boolean defines(String relation) {
        return relations.containsKey(relation);
    }

    public Rewrite rewriteFor(String relation) {
        Rewrite rewrite = relations.get(relation);
        if (rewrite == null) {
            throw new UnknownRelationException(name, relation);
        }
        return rewrite;
    }
}
