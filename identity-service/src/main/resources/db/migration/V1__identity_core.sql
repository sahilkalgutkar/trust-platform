-- Identity core.
--
-- Every tenant-scoped table carries tenant_id as the leading column of its own uniqueness
-- constraints, not just as a filter column: making (tenant_id, client_id) unique rather than
-- (client_id) is what lets two tenants independently register a client called "web-app" without
-- either one being able to collide with, or address, the other's.

CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    slug        VARCHAR(64)  NOT NULL UNIQUE,
    name        VARCHAR(255) NOT NULL,
    status      VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    tenant_id     UUID         NOT NULL REFERENCES tenants (id),
    email         VARCHAR(320) NOT NULL,
    password_hash VARCHAR(120) NOT NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
);

CREATE TABLE oauth_clients (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants (id),
    client_id           VARCHAR(128) NOT NULL,
    -- NULL for public clients (SPAs, native apps), which cannot keep a secret and must use PKCE.
    client_secret_hash  VARCHAR(120),
    name                VARCHAR(255) NOT NULL,
    redirect_uris       TEXT         NOT NULL DEFAULT '',
    grant_types         TEXT         NOT NULL DEFAULT 'authorization_code,refresh_token',
    scopes              TEXT         NOT NULL DEFAULT 'openid,profile',
    require_pkce        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_clients_tenant_client_id UNIQUE (tenant_id, client_id)
);

CREATE TABLE signing_keys (
    kid                  VARCHAR(64) PRIMARY KEY,
    tenant_id            UUID        NOT NULL REFERENCES tenants (id),
    algorithm            VARCHAR(16) NOT NULL DEFAULT 'RS256',
    public_jwk           TEXT        NOT NULL,
    -- AES-GCM ciphertext. The database never holds a usable private key on its own.
    private_key_wrapped  TEXT        NOT NULL,
    status               VARCHAR(16) NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at           TIMESTAMPTZ
);
-- One ACTIVE signing key per tenant at a time; retired keys stay published in JWKS until the
-- last token they signed has expired, so rotation never invalidates tokens already in flight.
CREATE UNIQUE INDEX uq_signing_keys_one_active
    ON signing_keys (tenant_id) WHERE status = 'ACTIVE';

CREATE TABLE authorization_codes (
    id                    UUID PRIMARY KEY,
    tenant_id             UUID         NOT NULL REFERENCES tenants (id),
    code_hash             VARCHAR(64)  NOT NULL,
    client_id             VARCHAR(128) NOT NULL,
    user_id               UUID         NOT NULL REFERENCES users (id),
    redirect_uri          TEXT         NOT NULL,
    scope                 TEXT         NOT NULL,
    nonce                 VARCHAR(255),
    code_challenge        VARCHAR(128),
    code_challenge_method VARCHAR(8),
    issued_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ  NOT NULL,
    consumed_at           TIMESTAMPTZ,
    CONSTRAINT uq_auth_codes_tenant_hash UNIQUE (tenant_id, code_hash)
);

CREATE TABLE refresh_tokens (
    id           UUID PRIMARY KEY,
    tenant_id    UUID         NOT NULL REFERENCES tenants (id),
    token_hash   VARCHAR(64)  NOT NULL,
    -- Every rotation keeps the family id of the token it replaced. Detecting a replay means
    -- revoking the whole family, not just the one token that was replayed.
    family_id    UUID         NOT NULL,
    client_id    VARCHAR(128) NOT NULL,
    user_id      UUID         NOT NULL REFERENCES users (id),
    scope        TEXT         NOT NULL,
    issued_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ  NOT NULL,
    consumed_at  TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    CONSTRAINT uq_refresh_tenant_hash UNIQUE (tenant_id, token_hash)
);
CREATE INDEX idx_refresh_family ON refresh_tokens (tenant_id, family_id);

-- Transactional outbox: an audit event is written in the same transaction as the thing it
-- records, so a Kafka outage can delay the audit trail but cannot lose an entry from it.
CREATE TABLE audit_outbox (
    id            UUID PRIMARY KEY,
    tenant_id     UUID        NOT NULL,
    payload       TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at  TIMESTAMPTZ
);
CREATE INDEX idx_outbox_unpublished ON audit_outbox (created_at) WHERE published_at IS NULL;
