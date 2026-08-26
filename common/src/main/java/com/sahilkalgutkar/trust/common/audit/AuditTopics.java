package com.sahilkalgutkar.trust.common.audit;

/** Kafka topic names shared by the producers (identity, authz) and the audit consumer. */
public final class AuditTopics {

    /** Every security-relevant event, keyed by tenant so one tenant's chain stays ordered. */
    public static final String AUDIT_EVENTS = "trust.audit.v1";

    private AuditTopics() {
    }
}
