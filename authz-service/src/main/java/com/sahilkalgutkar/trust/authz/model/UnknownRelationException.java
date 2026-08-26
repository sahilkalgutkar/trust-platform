package com.sahilkalgutkar.trust.authz.model;

/**
 * Thrown when a check names a relation the namespace does not define.
 *
 * <p>An undefined relation is an error rather than a denial on purpose: silently answering "no"
 * would turn a typo in a permission name into a permission that can never be granted, and it would
 * look exactly like a correctly-denied request in the logs.
 */
public class UnknownRelationException extends RuntimeException {

    public UnknownRelationException(String namespace, String relation) {
        super("Namespace '" + namespace + "' does not define relation '" + relation + "'");
    }
}
