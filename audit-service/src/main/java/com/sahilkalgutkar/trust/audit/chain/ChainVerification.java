package com.sahilkalgutkar.trust.audit.chain;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The result of walking a tenant's chain end to end.
 *
 * @param brokenAtSeq the first record that failed, or null when the chain is intact — the first
 *                    break is the useful number, since everything after it fails as a consequence
 * @param reason      which check failed, in a form an operator can act on
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ChainVerification(boolean intact, long recordsChecked, Long brokenAtSeq, String reason,
                                String headHash) {

    public static ChainVerification intact(long recordsChecked, String headHash) {
        return new ChainVerification(true, recordsChecked, null, null, headHash);
    }

    public static ChainVerification broken(long recordsChecked, long seq, String reason) {
        return new ChainVerification(false, recordsChecked, seq, reason, null);
    }
}
