package com.sahilkalgutkar.trust.audit.chain;

/**
 * What happened to one event on its way into the chain.
 *
 * @param seq  the position it took, or the position of the record that already held its event id
 */
public record AppendResult(Outcome outcome, long seq, String hash) {

    public enum Outcome {
        APPENDED,
        /** Kafka redelivered an event already in the chain; appending it again would be a lie. */
        DUPLICATE
    }

    public boolean appended() {
        return outcome == Outcome.APPENDED;
    }
}
