#!/usr/bin/env bash
#
# Proves the three services actually work together, which no single service's test suite can:
# a token minted by identity-service is accepted by authz-service, and the events both of them
# produce reach audit-service and chain correctly.
#
# Expects `docker compose up --wait` to have finished. Needs curl and jq.
set -euo pipefail

IDENTITY="${IDENTITY_URL:-http://localhost:8081}"
AUTHZ="${AUTHZ_URL:-http://localhost:8082}"
AUDIT="${AUDIT_URL:-http://localhost:8083}"
ADMIN_KEY="${ADMIN_API_KEY:-local-dev-admin-key}"
TENANT="smoke-$RANDOM"

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$1" >&2; exit 1; }

step "Creating tenant '$TENANT'"
TENANT_ID=$(curl -sf -X POST "$IDENTITY/admin/tenants" \
  -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d "{\"slug\":\"$TENANT\",\"name\":\"Smoke Test Inc\"}" | jq -r .id)
[ -n "$TENANT_ID" ] && [ "$TENANT_ID" != "null" ] || fail "no tenant id returned"
echo "tenant id: $TENANT_ID"

step "Registering a confidential client that may both check and write permissions"
CLIENT=$(curl -sf -X POST "$IDENTITY/t/$TENANT/admin/clients" \
  -H "X-Admin-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -d '{"clientId":"platform-api","name":"Platform API","redirectUris":[],
       "grantTypes":["client_credentials"],"scopes":["authz.check","authz.write"],
       "confidential":true,"requirePkce":false}')
CLIENT_SECRET=$(echo "$CLIENT" | jq -r .client_secret)
[ "$CLIENT_SECRET" != "null" ] || fail "client secret was not returned"

step "Exchanging client credentials for an access token"
TOKEN=$(curl -sf -X POST "$IDENTITY/t/$TENANT/oauth2/token" \
  -u "platform-api:$CLIENT_SECRET" \
  -d 'grant_type=client_credentials&scope=authz.check authz.write' | jq -r .access_token)
[ "$TOKEN" != "null" ] || fail "no access token issued"
echo "access token: ${TOKEN:0:32}…"

# base64url without padding is what a JWT carries; `base64 -d` wants the padding back, and wants
# the alphabet translated. Both GNU and BSD base64 accept -d, but only GNU ignores trailing junk.
b64url_decode() {
  local data="$1"
  local padding=$(( (4 - ${#data} % 4) % 4 ))
  while [ "$padding" -gt 0 ]; do data="${data}="; padding=$((padding - 1)); done
  printf '%s' "$data" | tr '_-' '/+' | base64 -d 2>/dev/null
}

step "Confirming the token's issuer and tenant claim"
CLAIMS=$(b64url_decode "$(echo "$TOKEN" | cut -d. -f2)")
echo "$CLAIMS" | jq -e --arg t "$TENANT_ID" '.tid == $t' >/dev/null \
  || fail "tid claim does not match the tenant: $CLAIMS"
echo "$CLAIMS" | jq -e --arg i "$IDENTITY/t/$TENANT" '.iss == $i' >/dev/null \
  || fail "issuer is not the tenant's own issuer: $CLAIMS"
echo "issuer: $(echo "$CLAIMS" | jq -r .iss)"

step "Defining a namespace in authz-service using that token"
curl -sf -X POST "$AUTHZ/t/$TENANT/v1/namespaces" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"document","relations":{
        "parent":{"type":"this"},
        "owner":{"type":"this"},
        "viewer":{"type":"union","children":[
          {"type":"this"},
          {"type":"computedUserset","relation":"owner"},
          {"type":"tupleToUserset","tupleset":"parent","computedUserset":"viewer"}]}}}' >/dev/null \
  || fail "authz-service rejected a token minted by identity-service"

step "Granting ownership, then checking a permission nobody wrote down"
ZOOKIE=$(curl -sf -X POST "$AUTHZ/t/$TENANT/v1/tuples" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"changes":[{"operation":"WRITE","namespace":"document","object":"readme",
                   "relation":"owner","subject":"user:ada"}]}' | jq -r .zookie)

# viewer was never granted directly: it has to be derived from owner via the rewrite rules.
ALLOWED=$(curl -sf -X POST "$AUTHZ/t/$TENANT/v1/check" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"namespace\":\"document\",\"object\":\"readme\",\"relation\":\"viewer\",
       \"subject\":\"user:ada\",\"zookie\":\"$ZOOKIE\"}" | jq -r .allowed)
[ "$ALLOWED" = "true" ] || fail "owner did not imply viewer"
echo "ada is a viewer by implication: $ALLOWED"

step "Checking that someone with no relationship is denied"
DENIED=$(curl -sf -X POST "$AUTHZ/t/$TENANT/v1/check" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"namespace":"document","object":"readme","relation":"viewer","subject":"user:mallory"}' \
  | jq -r .allowed)
[ "$DENIED" = "false" ] || fail "a stranger was allowed"

step "Waiting for the audit chain to catch up"
for _ in $(seq 1 30); do
  SEQ=$(curl -sf "$AUDIT/admin/tenants/$TENANT_ID/audit/head" -H "X-Admin-Key: $ADMIN_KEY" | jq -r .seq)
  [ "${SEQ:-0}" -ge 2 ] && break
  sleep 2
done
[ "${SEQ:-0}" -ge 2 ] || fail "audit events from identity and authz never arrived (head seq=$SEQ)"
echo "chain length: $SEQ"

step "Verifying the audit chain is intact"
VERIFY=$(curl -sf -X POST "$AUDIT/admin/tenants/$TENANT_ID/audit/verify" -H "X-Admin-Key: $ADMIN_KEY")
echo "$VERIFY" | jq -e '.intact == true' >/dev/null || fail "audit chain did not verify: $VERIFY"
echo "$VERIFY" | jq .

step "Confirming both services' events are in the log"
EVENTS=$(curl -sf "$AUDIT/admin/tenants/$TENANT_ID/audit/events?limit=50" -H "X-Admin-Key: $ADMIN_KEY")
echo "$EVENTS" | jq -e 'map(.action) | index("token.issued")' >/dev/null \
  || fail "identity-service's token.issued never reached the audit log"
echo "$EVENTS" | jq -e 'map(.action) | index("tuple.write")' >/dev/null \
  || fail "authz-service's tuple.write never reached the audit log"

printf '\n\033[32mSmoke test passed: all three services agree.\033[0m\n'
