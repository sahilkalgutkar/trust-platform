# trust-platform

[![CI](https://github.com/sahilkalgutkar/trust-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/sahilkalgutkar/trust-platform/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/sahilkalgutkar/trust-platform/branch/main/graph/badge.svg)](https://codecov.io/gh/sahilkalgutkar/trust-platform)
[![patch coverage](https://img.shields.io/badge/patch%20coverage-min%2080%25-blue.svg)](codecov.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Java 21](https://img.shields.io/badge/java-21-blue.svg)](https://adoptium.net/)

I build identity and entitlements infrastructure for a living, and I wanted a version of that work
I could actually show someone: an OpenID Connect provider, a Zanzibar-style authorization service,
and a tamper-evident audit log, written from the protocol up rather than assembled out of
off-the-shelf components.

Nothing here wraps Spring Security's OAuth support or an authorization SDK. The authorization code
flow, PKCE verification, refresh-token rotation with reuse detection, JWT signing and verification,
the relationship-based permission engine, and the audit hash chain are all implemented directly —
because the interesting part of this domain is the reasoning behind each rule, and you cannot show
that by configuring somebody else's library.

## What it does

**`identity-service` — an OpenID Connect provider.** Authorization code flow with PKCE, client
credentials, and refresh tokens that rotate on every use. Per-tenant RS256 signing keys, published
through a per-tenant JWKS endpoint and rotatable without invalidating tokens already in flight.
Private keys are wrapped with AES-256-GCM before they touch the database. Discovery, introspection,
revocation, and UserInfo are all there.

**`authz-service` — relationship-based authorization, after Google's Zanzibar paper.** Permissions
are not stored; they are *derived*. A namespace declares that a document's viewers are whoever was
granted `viewer` directly, plus everyone who is an `editor`, plus everyone who can view the parent
folder — and a check walks that definition at query time over the relationship tuples. Move a
document to a different folder and its access changes with it, because nothing about the document
was ever written down. Supports usersets (`group:engineering#member`), nested groups, unions,
intersections, exclusions, an `expand` API for answering "why does this person have access", a
Redis check cache, and Zanzibar's consistency tokens.

**`audit-service` — an audit log that cannot be quietly edited.** Both services publish security
events through a transactional outbox to Kafka; this one consumes them and chains them with
SHA-256, per tenant. Each record's hash covers the record before it, so editing or deleting any row
invalidates every hash after it and the verification endpoint reports the exact position where the
chain breaks.

Everything is multi-tenant, and the tenant boundary is enforced in the generated SQL rather than in
service code.

## Why these three, together

They are the three halves of one question — *who are you*, *what may you do*, and *what happened* —
and each one is only as good as its handoff to the next.

```
                     ┌────────────────────┐
  login / token ────▶│  identity-service  │  RS256 access token, per-tenant issuer + keys
                     └─────────┬──────────┘
                               │  JWKS (fetched and cached)
                               ▼
  "may Ada view    ┌────────────────────┐   ┌───────┐
   this document?" │   authz-service    │──▶│ Redis │  check cache, keyed by revision
                   └─────────┬──────────┘   └───────┘
                             │
       ┌─────────────────────┴────────────────┐
       │  audit events, via transactional outbox
       ▼                                      ▼
  ┌─────────┐                        ┌────────────────┐
  │  Kafka  │───────────────────────▶│  audit-service │  SHA-256 hash chain per tenant
  └─────────┘   keyed by tenant      └────────────────┘
```

The authorization service never takes a tenant id from a URL. It reads the `tid` claim out of a
token the identity service signed, verifies it offline against that tenant's JWKS, and uses *that*
as the tenant for every query it makes. A caller cannot reach another tenant's data by editing a
path, because the path is not what decides.

## The parts I think are worth reading

**Refresh token rotation with reuse detection** — [`TokenService`](identity-service/src/main/java/com/sahilkalgutkar/trust/identity/oauth/TokenService.java).
Every refresh consumes the presented token and issues a new one carrying the same *family* id. A
stolen token therefore works only until the legitimate client refreshes once; after that, one of
the two parties presents a consumed token, and the whole family is revoked. The provider cannot
tell the thief from the victim, so it stops trusting the lineage rather than guessing.

**Detecting a replay has to outlive the request that detected it** —
[`CompromiseResponder`](identity-service/src/main/java/com/sahilkalgutkar/trust/identity/oauth/CompromiseResponder.java).
This class exists because of a bug my integration tests caught and my unit tests could not. The
revocation used to run inline and then throw `invalid_grant` to reject the request — and that
exception rolled back the very transaction the revocation had just been written in. The replay was
detected, reported, and then silently forgiven. It now commits in its own transaction.

**The tenant predicate is not optional** —
[`TenantIdentifierResolver`](identity-service/src/main/java/com/sahilkalgutkar/trust/identity/config/TenantIdentifierResolver.java).
Tenant scoping runs through Hibernate's discriminator-based multi-tenancy, so `findByEmail(...)`
generates SQL that carries a tenant predicate whether or not anyone remembered to ask for one. When
no tenant is bound, the resolver returns the nil UUID rather than null or a default — the query
still runs, and matches nothing. Fail closed.

**The check engine** — [`CheckEngine`](authz-service/src/main/java/com/sahilkalgutkar/trust/authz/engine/CheckEngine.java).
Depth-first and short-circuiting, with a visited set so that a group which transitively contains
itself terminates with a denial instead of a stack overflow, and a depth limit for hierarchies that
are finite but absurd. `expand` renders the same rules as a tree, because `check` answers yes or no
and "why" is the question an operator actually has at 3am.

**Consistency tokens** — [`Zookie`](authz-service/src/main/java/com/sahilkalgutkar/trust/authz/model/Zookie.java).
An application that removes someone from a document and then re-shares it has ordered those two
operations, but nothing forces the permission cache to observe them in that order — so a stale
cached check can let the removed user back in. A caller that passes back the token it got from its
write is saying "do not answer me from a snapshot older than this."

**Four ways of interfering with an audit log, and the check that catches each** —
[`AuditChainVerifier`](audit-service/src/main/java/com/sahilkalgutkar/trust/audit/chain/AuditChainVerifier.java).
Rewriting a record breaks its hash. Rewriting it *and* recomputing its hash breaks the next
record's link. Deleting a record leaves a gap in the sequence that the hashes alone would not
notice. And editing only an indexed column — the ones every query and export actually read — is
caught by checking those columns against the signed payload.

## What the tests are for

**362 unit tests and 69 integration tests, at 92% line and 86% branch coverage.** The integration
tests run against real Postgres, Redis, and Kafka through Testcontainers, because the behaviour
being tested is often the database's: the tenant discriminator, the partial unique index that makes
key rotation safe, the constraint that lets two tenants both register a client called `web-app`.

A large share of the suite is adversarial — every negative case below is a published attack rather
than an invented one, and each produces a token or a request that *parses*:

| Attack | Test |
| --- | --- |
| `alg: none` downgrade | `JwtIssuerVerifierTest.anUnsignedTokenIsRejected` |
| HS256 forgery using the public key as the HMAC secret | `…aTokenReSignedWithHmacUsingThePublicKeyIsRejected` |
| PKCE downgrade — claiming `plain` and replaying the challenge | `PkceValidatorTest.anS256ChallengeCannotBeDowngraded…` |
| Confused deputy — redeeming another client's code | `TokenServiceTest.aCodeIssuedToAnotherClientIsRejectedAndBurned` |
| Stolen refresh token replayed after rotation | `…presentingAnAlreadyRotatedTokenRevokesTheWholeFamily` |
| Open redirect via an unregistered `redirect_uri` | `OAuthFlowIT.anUnregisteredRedirectUriIsRefusedWithoutARedirect` |
| Cross-tenant code redemption, token replay, and introspection | `TenantIsolationIT` (12 tests) |
| Editing the audit table with plain SQL | `AuditPipelineIT.editingAStoredRecordWithSqlIsDetected` |

`TenantIsolationIT` deliberately gives both tenants the *same* client id and the *same* user email,
so that any query which lost its tenant predicate would return the other tenant's row and one of
those tests would pass where it expects a rejection.

## Running it

```bash
docker compose up --build
./scripts/smoke-test.sh
```

The smoke test — the same one CI runs — creates a tenant, mints a token from the identity service,
uses that token to define a namespace and grant a permission in the authorization service, checks a
permission that was never written down anywhere, and then verifies that both services' events
arrived in the audit chain intact. [`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md) does the same thing
by hand, with the requests and responses spelled out.

To run the tests:

```bash
./mvnw verify
```

Unit tests run under Surefire; the Testcontainers integration tests run under Failsafe and need a
Docker daemon. If Testcontainers reports "Could not find a valid Docker environment" on a recent
Docker Desktop, override the negotiated API version: `./mvnw verify -Ddocker.api.version=1.44`.

## Built with

Java 21, Spring Boot 3.3, Hibernate 6 (discriminator multi-tenancy), PostgreSQL 16, Flyway, Redis,
Kafka, Nimbus JOSE+JWT, Testcontainers, JaCoCo. Multi-module Maven; one database per service.

## What I left out, and why

- **A login UI.** The authorization endpoint returns JSON describing the pending request instead of
  rendering a consent screen. The validation rules are the part worth reading, and they do not
  change when a template engine is added — but a browser flow would have put a headless-browser
  suite between a reader and them.
- **Zanzibar's leopard index.** Deeply nested group membership is evaluated by recursion rather than
  by a precomputed transitive closure. That is a throughput decision, not a correctness one, and the
  index would have obscured the semantics this repository is meant to show.
- **Auditing individual permission checks.** A busy authorization service answers millions of them;
  logging every read would drown the record of the writes that actually changed who can do what.
  Grants and revocations are audited. Check volume belongs in metrics.
- **A KMS.** Signing keys are wrapped with AES-256-GCM using a master key from configuration, which
  protects a leaked database backup and nothing more. The seam is one class wide
  ([`KeyEncryptor`](identity-service/src/main/java/com/sahilkalgutkar/trust/identity/jwt/KeyEncryptor.java))
  and is where a real deployment would call out to KMS or an HSM.
- **Making the audit log unforgeable.** The hash chain makes tampering *detectable*, not impossible
  — someone who can rewrite the whole table can recompute the whole chain. That is why the chain
  head is exposed as its own endpoint: the value is meant to be recorded somewhere the database
  cannot reach.
