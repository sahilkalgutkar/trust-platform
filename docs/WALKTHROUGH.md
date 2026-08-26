# Walkthrough

The same path `scripts/smoke-test.sh` takes, by hand. Start the platform first:

```bash
docker compose up --build
```

Three services come up: identity on `:8081`, authorization on `:8082`, audit on `:8083`.

Throughout, `local-dev-admin-key` is the administrative key from `docker-compose.yml`. In a real
deployment these control-plane endpoints sit behind mTLS or the platform's own admin identity.

---

## 1. Create a tenant

```bash
curl -s -X POST http://localhost:8081/admin/tenants \
  -H 'X-Admin-Key: local-dev-admin-key' -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme Inc"}'
```

```json
{ "id": "8f14e45f-ceea-467a-9e5a-0b2f0f83c1de", "slug": "acme", "name": "Acme Inc" }
```

Keep that `id` — it is the tenant id that appears in every access token's `tid` claim and in the
audit log's URLs.

Everything from here lives under `/t/acme/`. That prefix is not cosmetic: it is what makes the
issuer, the discovery document, and the JWKS per-tenant, so a relying party configured for `acme`
has no route to another tenant's metadata even by construction.

## 2. Look at the tenant's OpenID configuration

```bash
curl -s http://localhost:8081/t/acme/.well-known/openid-configuration | jq
```

```json
{
  "issuer": "http://localhost:8081/t/acme",
  "authorization_endpoint": "http://localhost:8081/t/acme/oauth2/authorize",
  "token_endpoint": "http://localhost:8081/t/acme/oauth2/token",
  "jwks_uri": "http://localhost:8081/t/acme/oauth2/jwks",
  "code_challenge_methods_supported": ["S256", "plain"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

The tenant's signing key is generated lazily, the first time it is needed. Ask for the JWKS now and
you will see it appear — public halves only:

```bash
curl -s http://localhost:8081/t/acme/oauth2/jwks | jq
```

## 3. Register a user and a public client

```bash
curl -s -X POST http://localhost:8081/t/acme/admin/users \
  -H 'X-Admin-Key: local-dev-admin-key' -H 'Content-Type: application/json' \
  -d '{"email":"ada@acme.test","password":"correct horse battery staple"}'

curl -s -X POST http://localhost:8081/t/acme/admin/clients \
  -H 'X-Admin-Key: local-dev-admin-key' -H 'Content-Type: application/json' \
  -d '{"clientId":"web-app","name":"Web App",
       "redirectUris":["https://app.acme.test/callback"],
       "grantTypes":["authorization_code","refresh_token"],
       "scopes":["openid","profile"],
       "confidential":false,"requirePkce":true}'
```

A public client — an SPA or a native app — cannot keep a secret, so it proves itself with PKCE
instead. Register it as `"confidential": true` and the response carries a `client_secret`, returned
exactly once; only its hash is stored.

## 4. Run the authorization code flow

PKCE first. The verifier is a random string; the challenge is its SHA-256, base64url-encoded:

```bash
VERIFIER=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -binary -sha256 | openssl base64 -A \
  | tr '+/' '-_' | tr -d '=')
```

`GET /oauth2/authorize` validates the request and returns what a login screen would need to render:

```bash
curl -s -G http://localhost:8081/t/acme/oauth2/authorize \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'client_id=web-app' \
  --data-urlencode 'redirect_uri=https://app.acme.test/callback' \
  --data-urlencode 'scope=openid profile' \
  --data-urlencode 'state=xyz' \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode 'code_challenge_method=S256' | jq
```

Try it with `redirect_uri=https://evil.test/steal` and you get a `400` that stays on this server.
It never redirects to report that a redirect URI is untrusted — doing so *would be* the open
redirect.

`POST` to the same endpoint with credentials, and it redirects back with a code:

```bash
curl -s -i -X POST http://localhost:8081/t/acme/oauth2/authorize \
  -d 'response_type=code' -d 'client_id=web-app' \
  -d 'redirect_uri=https://app.acme.test/callback' \
  -d 'scope=openid profile' -d 'state=xyz' \
  -d "code_challenge=$CHALLENGE" -d 'code_challenge_method=S256' \
  -d 'username=ada@acme.test' --data-urlencode 'password=correct horse battery staple' \
  | grep -i location
```

```
location: https://app.acme.test/callback?code=Q0h5b2…&state=xyz
```

Exchange the code, presenting the verifier whose hash was committed to at the start:

```bash
curl -s -X POST http://localhost:8081/t/acme/oauth2/token \
  -d 'grant_type=authorization_code' -d 'client_id=web-app' \
  -d "code=$CODE" -d 'redirect_uri=https://app.acme.test/callback' \
  -d "code_verifier=$VERIFIER" | jq
```

```json
{
  "access_token": "eyJraWQiOiI…",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "3sKp9Nq…",
  "id_token": "eyJraWQiOiI…",
  "scope": "openid profile"
}
```

**Present the same code again.** It fails with `invalid_grant` — and the refresh token the first
exchange produced is now revoked too, because a code presented twice is assumed to have leaked.

## 5. Watch a stolen refresh token burn its own family

Refresh once. You get a new refresh token; the old one is consumed:

```bash
curl -s -X POST http://localhost:8081/t/acme/oauth2/token \
  -d 'grant_type=refresh_token' -d 'client_id=web-app' -d "refresh_token=$REFRESH" | jq
```

Now present the *original* one again, as a thief holding a copy would:

```json
{ "error": "invalid_grant", "error_description": "Grant rejected" }
```

The rotated token is dead as well. The provider cannot tell which of the two callers is the
attacker, so it stops trusting the lineage rather than guessing — and writes a
`refresh.reuse_detected` event to the audit log on the way out.

## 6. Ask the authorization service a question

The authorization service needs a token carrying `authz.check` / `authz.write`. Register a
confidential client for it and use client credentials:

```bash
SECRET=$(curl -s -X POST http://localhost:8081/t/acme/admin/clients \
  -H 'X-Admin-Key: local-dev-admin-key' -H 'Content-Type: application/json' \
  -d '{"clientId":"platform-api","name":"Platform API","redirectUris":[],
       "grantTypes":["client_credentials"],"scopes":["authz.check","authz.write"],
       "confidential":true,"requirePkce":false}' | jq -r .client_secret)

TOKEN=$(curl -s -X POST http://localhost:8081/t/acme/oauth2/token \
  -u "platform-api:$SECRET" \
  -d 'grant_type=client_credentials&scope=authz.check authz.write' | jq -r .access_token)
```

Define a namespace. This is where permissions are *described* rather than stored:

```bash
curl -s -X POST http://localhost:8082/t/acme/v1/namespaces \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"document","relations":{
        "parent":{"type":"this"},
        "owner":{"type":"this"},
        "editor":{"type":"union","children":[
          {"type":"this"},
          {"type":"computedUserset","relation":"owner"}]},
        "viewer":{"type":"union","children":[
          {"type":"this"},
          {"type":"computedUserset","relation":"editor"},
          {"type":"tupleToUserset","tupleset":"parent","computedUserset":"viewer"}]}}}'
```

Read that as: viewers are whoever was granted `viewer` directly, **plus** everyone who is an
`editor`, **plus** everyone who can view the parent folder. Editors are whoever was granted
`editor` directly plus every `owner`.

Grant exactly one thing:

```bash
ZOOKIE=$(curl -s -X POST http://localhost:8082/t/acme/v1/tuples \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"changes":[{"operation":"WRITE","namespace":"document","object":"readme",
                   "relation":"owner","subject":"user:ada"}]}' | jq -r .zookie)
```

Then ask about a permission nobody wrote down:

```bash
curl -s -X POST http://localhost:8082/t/acme/v1/check \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"namespace\":\"document\",\"object\":\"readme\",\"relation\":\"viewer\",
       \"subject\":\"user:ada\",\"zookie\":\"$ZOOKIE\"}" | jq
```

```json
{ "allowed": true, "zookie": "cjE=", "cached": false, "tuplesRead": 1, "depth": 3 }
```

`depth: 3` is the derivation: `viewer` → `editor` → `owner`. Ask again and `cached` flips to
`true`. Pass the zookie from a write and the cache is bypassed if it is older than that revision —
which is what stops a revoke from being read back stale.

### Groups and inheritance

```bash
# Ada's colleagues, via a group
curl -s -X POST http://localhost:8082/t/acme/v1/tuples -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"changes":[
    {"operation":"WRITE","namespace":"group","object":"engineering","relation":"member","subject":"user:bob"},
    {"operation":"WRITE","namespace":"document","object":"readme","relation":"viewer","subject":"group:engineering#member"}]}'
```

Bob is now a viewer, and removing him from the group removes his access — with no write against the
document at all. The same holds for folders: point `document:spec` at `folder:eng` with a `parent`
tuple, and it inherits every viewer the folder chain has.

### Why does this person have access?

```bash
curl -s -X POST http://localhost:8082/t/acme/v1/expand \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"namespace":"document","object":"readme","relation":"viewer"}' | jq
```

The tree mirrors the namespace's rules, so a surprising allow can be traced to the exact tuple and
the exact rule that produced it.

## 7. Read the audit log

Both services have been publishing events all along — through a transactional outbox, so a Kafka
outage would have delayed the audit trail rather than losing entries from it.

```bash
TENANT_ID=8f14e45f-ceea-467a-9e5a-0b2f0f83c1de   # from step 1

curl -s "http://localhost:8083/admin/tenants/$TENANT_ID/audit/events?limit=20" \
  -H 'X-Admin-Key: local-dev-admin-key' | jq
```

```json
[
  { "seq": 5, "action": "tuple.write",  "actor": "client:platform-api",
    "prevHash": "9f2c…", "hash": "41ab…" },
  { "seq": 4, "action": "refresh.reuse_detected", "actor": "client:web-app",
    "outcome": "DENIED", "prevHash": "77de…", "hash": "9f2c…" }
]
```

Each `prevHash` is the previous record's `hash`. Verify the whole chain:

```bash
curl -s -X POST "http://localhost:8083/admin/tenants/$TENANT_ID/audit/verify" \
  -H 'X-Admin-Key: local-dev-admin-key' | jq
```

```json
{ "intact": true, "recordsChecked": 5, "headHash": "41ab…" }
```

### Try to tamper with it

Edit a record directly in the database — the thing an attacker with database access would do:

```bash
docker compose exec postgres psql -U trust -d trust_audit -c \
  "UPDATE audit_events SET actor = 'user:someone-else' WHERE seq = 2;"
```

```bash
curl -s -X POST "http://localhost:8083/admin/tenants/$TENANT_ID/audit/verify" \
  -H 'X-Admin-Key: local-dev-admin-key' | jq
```

```json
{
  "intact": false,
  "recordsChecked": 1,
  "brokenAtSeq": 2,
  "reason": "Indexed columns disagree with the signed payload"
}
```

Deleting the row instead reports `Missing record at position 2`. Rewriting the payload *and*
recomputing that record's own hash still fails, one record later, with `Record does not chain to
its predecessor`.

That last point is the honest limit of this design: someone who can rewrite the whole table can
recompute the whole chain. It makes tampering *detectable*, not impossible — which is why
`/audit/head` exists as its own endpoint. The head hash is meant to be recorded somewhere the
database cannot reach.
