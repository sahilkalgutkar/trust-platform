-- Relationship-based authorization storage, after Google's Zanzibar paper.
--
-- Two tables carry the whole model: a namespace's *configuration* (what relations exist and how
-- they derive from one another) and the *relation tuples* (who is actually related to what). Every
-- permission question in the system is answered by evaluating the first against the second.

CREATE TABLE namespaces (
    tenant_id   UUID         NOT NULL,
    name        VARCHAR(64)  NOT NULL,
    config      TEXT         NOT NULL,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, name)
);

-- A monotonic counter shared by every tenant. Zanzibar's zookies encode a snapshot timestamp; this
-- is the same idea with a sequence, which is what a single Postgres can offer honestly. Sharing one
-- sequence across tenants costs nothing but makes a zookie meaningless outside its own tenant,
-- which is the desired property anyway.
CREATE SEQUENCE authz_revision START WITH 1;

CREATE TABLE relation_tuples (
    id                UUID         PRIMARY KEY,
    tenant_id         UUID         NOT NULL,
    namespace         VARCHAR(64)  NOT NULL,
    object_id         VARCHAR(255) NOT NULL,
    relation          VARCHAR(64)  NOT NULL,
    -- The subject is either a concrete subject (user:ada) or a userset (group:eng#member).
    -- subject_relation is what distinguishes the two, and its presence is what makes group
    -- membership expressible without a separate table.
    subject_type      VARCHAR(64)  NOT NULL,
    subject_id        VARCHAR(255) NOT NULL,
    -- Empty string rather than NULL for "no relation": Postgres treats NULLs as distinct in a
    -- unique constraint, so a nullable column here would happily accept the same direct tuple
    -- twice. An empty string is comparable, and the model has no use for a third state.
    subject_relation  VARCHAR(64)  NOT NULL DEFAULT '',
    revision          BIGINT       NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_tuple UNIQUE (tenant_id, namespace, object_id, relation,
                                subject_type, subject_id, subject_relation)
);

-- The access path a check actually walks: "given this object and relation, who is related?"
CREATE INDEX idx_tuples_object
    ON relation_tuples (tenant_id, namespace, object_id, relation);

-- The reverse path, for expanding a subject's access and for listing what a user can reach.
CREATE INDEX idx_tuples_subject
    ON relation_tuples (tenant_id, subject_type, subject_id, subject_relation);

-- Each service owns its own database, so each owns its own outbox table. The duplication with
-- identity-service is deliberate: sharing one would couple two services' schemas and put a
-- cross-service migration in the path of every change to either.
CREATE TABLE audit_outbox (
    id            UUID PRIMARY KEY,
    tenant_id     UUID        NOT NULL,
    payload       TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at  TIMESTAMPTZ
);
CREATE INDEX idx_outbox_unpublished ON audit_outbox (created_at) WHERE published_at IS NULL;
