package com.sahilkalgutkar.trust.authz.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Who (or what) a tuple points at: either a concrete subject or a userset.
 *
 * <p>{@code user:ada} is a subject. {@code group:engineering#member} is a <em>userset</em> — "every
 * subject that has the {@code member} relation on {@code group:engineering}". Collapsing both into
 * one type is what lets a single tuple table express group membership, nested groups, and
 * inherited permissions without any of them being a special case in the storage layer.
 */
public record SubjectRef(String type, String id, String relation) {

    public SubjectRef {
        if (type == null || type.isBlank()) {
            throw new IllegalArgumentException("Subject type is required");
        }
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("Subject id is required");
        }
        relation = relation == null ? "" : relation;
    }

    public static SubjectRef subject(String type, String id) {
        return new SubjectRef(type, id, "");
    }

    public static SubjectRef userset(String type, String id, String relation) {
        return new SubjectRef(type, id, relation);
    }

    /** Parses {@code type:id} or {@code type:id#relation}. */
    @JsonCreator
    public static SubjectRef parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Subject is required");
        }
        int colon = value.indexOf(':');
        if (colon <= 0 || colon == value.length() - 1) {
            throw new IllegalArgumentException(
                    "Subject must look like type:id or type:id#relation, got: " + value);
        }
        String type = value.substring(0, colon);
        String rest = value.substring(colon + 1);
        int hash = rest.indexOf('#');
        if (hash < 0) {
            return subject(type, rest);
        }
        if (hash == 0 || hash == rest.length() - 1) {
            throw new IllegalArgumentException("Malformed userset: " + value);
        }
        return userset(type, rest.substring(0, hash), rest.substring(hash + 1));
    }

    public boolean isUserset() {
        return !relation.isEmpty();
    }

    @JsonValue
    @Override
    public String toString() {
        return isUserset() ? type + ":" + id + "#" + relation : type + ":" + id;
    }
}
