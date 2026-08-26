package com.sahilkalgutkar.trust.audit.chain;

import java.time.Instant;

/**
 * The current tip of a tenant's chain.
 *
 * <p>This is the value worth copying somewhere the database cannot reach — an operator's records, a
 * separate account, a printout. Verification proves the chain is internally consistent; comparing
 * the head against one recorded earlier is what proves nobody rebuilt it from scratch.
 */
public record ChainHead(long seq, String hash, Instant recordedAt) {
}
