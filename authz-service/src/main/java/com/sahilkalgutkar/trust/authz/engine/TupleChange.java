package com.sahilkalgutkar.trust.authz.engine;

import com.sahilkalgutkar.trust.authz.model.SubjectRef;

/** One relationship to create or remove. */
public record TupleChange(Operation operation, String namespace, String objectId, String relation,
                          SubjectRef subject) {

    public enum Operation {
        WRITE,
        DELETE
    }

    public TupleChange {
        if (operation == null) {
            throw new IllegalArgumentException("operation must be WRITE or DELETE");
        }
        if (namespace == null || namespace.isBlank()) {
            throw new IllegalArgumentException("namespace is required");
        }
        if (objectId == null || objectId.isBlank()) {
            throw new IllegalArgumentException("object is required");
        }
        if (relation == null || relation.isBlank()) {
            throw new IllegalArgumentException("relation is required");
        }
        if (subject == null) {
            throw new IllegalArgumentException("subject is required");
        }
    }

    @Override
    public String toString() {
        return namespace + ":" + objectId + "#" + relation + "@" + subject;
    }
}
