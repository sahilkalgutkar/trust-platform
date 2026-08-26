-- The tamper-evident audit log.
--
-- Each tenant gets its own chain: record N's hash covers record N-1's hash together with record N's
-- own canonical bytes, so editing or deleting any row invalidates every hash after it. That does not
-- make the log unforgeable — an attacker with full write access could recompute the entire chain —
-- which is why the chain head is also published outward, where a database rewrite cannot reach it.
-- What it does buy is that tampering can no longer be *quiet*.

CREATE TABLE audit_events (
    id             UUID PRIMARY KEY,
    tenant_id      UUID         NOT NULL,
    -- Position in this tenant's chain, starting at 1.
    seq            BIGINT       NOT NULL,
    -- The producer's idempotency key. Kafka delivery is at-least-once, and appending the same
    -- event twice would put a real gap between the log and what actually happened.
    event_id       VARCHAR(64)  NOT NULL,
    actor          VARCHAR(255) NOT NULL,
    action         VARCHAR(128) NOT NULL,
    resource_type  VARCHAR(64),
    resource_id    VARCHAR(255),
    outcome        VARCHAR(16)  NOT NULL,
    occurred_at    TIMESTAMPTZ  NOT NULL,
    -- The exact canonical JSON that was hashed, and the authoritative copy of the event. The
    -- columns above are a denormalized index over it for querying; verification checks both that
    -- the chain of hashes holds AND that those columns still agree with this payload, so editing
    -- a searchable column without touching the payload does not slip through.
    payload        TEXT         NOT NULL,
    prev_hash      VARCHAR(64)  NOT NULL,
    hash           VARCHAR(64)  NOT NULL,
    recorded_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Two writers racing for the same position lose one insert rather than forking the chain.
    CONSTRAINT uq_audit_seq UNIQUE (tenant_id, seq),
    CONSTRAINT uq_audit_event_id UNIQUE (tenant_id, event_id)
);

CREATE INDEX idx_audit_tenant_seq ON audit_events (tenant_id, seq DESC);
CREATE INDEX idx_audit_tenant_occurred ON audit_events (tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_tenant_action ON audit_events (tenant_id, action);
