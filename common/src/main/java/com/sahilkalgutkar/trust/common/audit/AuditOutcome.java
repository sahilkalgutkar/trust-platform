package com.sahilkalgutkar.trust.common.audit;

/** Whether the audited attempt succeeded — denials are the records auditors actually want. */
public enum AuditOutcome {
    SUCCESS,
    DENIED,
    FAILURE
}
