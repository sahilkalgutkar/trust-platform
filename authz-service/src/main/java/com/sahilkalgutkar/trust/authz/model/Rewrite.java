package com.sahilkalgutkar.trust.authz.model;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.List;

/**
 * A userset rewrite rule: how one relation is derived from tuples and other relations.
 *
 * <p>This is the part of Zanzibar that makes it more than a join table. Rather than materialising
 * "who can view this document", a namespace <em>declares</em> that viewers are the people directly
 * granted {@code viewer}, plus everyone who is an {@code editor}, plus everyone who can view the
 * parent folder — and the check walks that definition at query time. Permissions stay correct when
 * a folder is re-shared, because nothing about the document was ever written down.
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type")
@JsonSubTypes({
        @JsonSubTypes.Type(value = Rewrite.This.class, name = "this"),
        @JsonSubTypes.Type(value = Rewrite.ComputedUserset.class, name = "computedUserset"),
        @JsonSubTypes.Type(value = Rewrite.TupleToUserset.class, name = "tupleToUserset"),
        @JsonSubTypes.Type(value = Rewrite.Union.class, name = "union"),
        @JsonSubTypes.Type(value = Rewrite.Intersection.class, name = "intersection"),
        @JsonSubTypes.Type(value = Rewrite.Exclusion.class, name = "exclusion"),
})
public sealed interface Rewrite {

    /** The tuples written directly against this object and relation. */
    record This() implements Rewrite {
    }

    /** Whoever holds {@code relation} on the same object — how {@code editor} implies {@code viewer}. */
    record ComputedUserset(String relation) implements Rewrite {

        public ComputedUserset {
            if (relation == null || relation.isBlank()) {
                throw new IllegalArgumentException("computedUserset requires a relation");
            }
        }
    }

    /**
     * Follows {@code tupleset} to another object, then evaluates {@code computedUserset} there —
     * how a document inherits viewers from the folder it lives in.
     */
    record TupleToUserset(String tupleset, String computedUserset) implements Rewrite {

        public TupleToUserset {
            if (tupleset == null || tupleset.isBlank()) {
                throw new IllegalArgumentException("tupleToUserset requires a tupleset relation");
            }
            if (computedUserset == null || computedUserset.isBlank()) {
                throw new IllegalArgumentException("tupleToUserset requires a computedUserset relation");
            }
        }
    }

    record Union(List<Rewrite> children) implements Rewrite {

        public Union {
            children = requireChildren(children, "union");
        }
    }

    record Intersection(List<Rewrite> children) implements Rewrite {

        public Intersection {
            children = requireChildren(children, "intersection");
        }
    }

    /** {@code base} minus {@code subtract} — the only way to express a deny in this model. */
    record Exclusion(Rewrite base, Rewrite subtract) implements Rewrite {

        public Exclusion {
            if (base == null || subtract == null) {
                throw new IllegalArgumentException("exclusion requires both base and subtract");
            }
        }
    }

    private static List<Rewrite> requireChildren(List<Rewrite> children, String node) {
        if (children == null || children.isEmpty()) {
            throw new IllegalArgumentException(node + " requires at least one child");
        }
        return List.copyOf(children);
    }
}
