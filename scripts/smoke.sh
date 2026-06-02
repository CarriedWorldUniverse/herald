#!/usr/bin/env bash
# herald end-to-end smoke: the golden-path MVP loop with a REAL casket key,
# driven THROUGH interchange. Admin provisioning is the gRPC AdminService behind
# the gateway with identity-derived authz — there is no static admin token, so
# this smoke logs in as the platform-admin owner (cwadmin) and provisions via
# the gateway's HTTP↔gRPC admin edge. (For the comprehensive suite, run
# cwb-conformance `-layers all`; this is the quick local loop.)
#
# Usage:
#   GATEWAY=http://127.0.0.1:8080 OWNER_PASSWORD=... bash scripts/smoke.sh
# Defaults target a local gateway; OWNER_EMAIL defaults to cwadmin@carriedworld.com.
set -uo pipefail
GATEWAY="${GATEWAY:-http://127.0.0.1:8080}"
HPATH="${HERALD_PATH:-/herald}"
B="$GATEWAY$HPATH"            # herald, fronted by the gateway
OWNER_EMAIL="${OWNER_EMAIL:-cwadmin@carriedworld.com}"
OWNER_PASSWORD="${OWNER_PASSWORD:?set OWNER_PASSWORD (the genesis owner password)}"
jqr() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"; }
login() { # login <username> <password> -> access_token
  curl -fsS -X POST "$B/token" \
    -d "grant_type=password&username=$1&password=$2" | jqr access_token
}

echo "== healthz =="; curl -fsS "$B/healthz"; echo
echo "== discovery =="; curl -fsS "$B/.well-known/openid-configuration" | python3 -c "import sys,json;d=json.load(sys.stdin);print('issuer',d['issuer'],'| token_ep',d['token_endpoint'])"
echo "== jwks =="; curl -fsS "$B/jwks" | python3 -c "import sys,json;k=json.load(sys.stdin)['keys'][0];print('kty',k['kty'],'crv',k['crv'],'kid',k['kid'])"

echo "== platform-admin owner (cwadmin) logs in =="
OTOK=$(login "$OWNER_EMAIL" "$OWNER_PASSWORD")
[ -n "$OTOK" ] || { echo "FAIL: cwadmin login"; exit 1; }
hdr_admin=(-H "Authorization: Bearer $OTOK")

echo "== create org (via gateway gRPC admin) =="
ORG=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/orgs" -d '{"name":"acme"}' | jqr id); echo "org=$ORG"
echo "== create human =="
HUMAN=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/orgs/$ORG/humans" -d '{"display_name":"jacinta"}' | jqr id); echo "human=$HUMAN"
echo "== set human password =="
HUMAN_PW="smoke-human-$RANDOM-pw"
curl -fsS "${hdr_admin[@]}" -X POST "$B/api/humans/$HUMAN/password" -d "{\"password\":\"$HUMAN_PW\"}" >/dev/null && echo "password set"

# Derive a real casket key for the bootstrap agent via a tiny Go helper.
echo "== derive bootstrap casket key =="
read -r BS_PUB_B64 BS_PRIV_B64 < <(go run ./cmd/herald-keytool 2>/dev/null derive "seed-for-smoke-test-32bytes-pad!" bootstrap)
echo "bootstrap pub=${BS_PUB_B64:0:16}..."

echo "== admin creates bootstrap agent (agent:create) =="
BS=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/orgs/$ORG/agents" \
  -d "{\"display_name\":\"bootstrap\",\"responsible_human\":\"$HUMAN\",\"casket_pubkey\":\"$BS_PUB_B64\",\"scopes\":[\"agent:create\"]}" | jqr id)
echo "bootstrap_agent=$BS"

echo "== bootstrap agent mints token (casket jwt-bearer) =="
ASSERTION=$(go run ./cmd/herald-keytool 2>/dev/null assert "$BS_PRIV_B64" "$BS" "$B/token")
TOK=$(curl -fsS -X POST "$B/token" -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$ASSERTION" | jqr access_token)
echo "bootstrap token=${TOK:0:24}..."
[ -n "$TOK" ] || { echo "FAIL: no token"; exit 1; }

echo "== SELF-PROVISION: bootstrap agent creates 'anvil' =="
read -r ANVIL_PUB_B64 ANVIL_PRIV_B64 < <(go run ./cmd/herald-keytool 2>/dev/null derive "seed-for-smoke-test-32bytes-pad!" anvil)
ANVIL=$(curl -fsS -H "Authorization: Bearer $TOK" -X POST "$B/api/agents" \
  -d "{\"display_name\":\"anvil\",\"casket_pubkey\":\"$ANVIL_PUB_B64\",\"scopes\":[\"repo:write\"]}")
ANVIL_ID=$(echo "$ANVIL" | jqr id); ANVIL_STATUS=$(echo "$ANVIL" | jqr status)
echo "anvil=$ANVIL_ID status=$ANVIL_STATUS (expect pending)"

echo "== pending anvil CANNOT mint =="
A_ASSERT=$(go run ./cmd/herald-keytool 2>/dev/null assert "$ANVIL_PRIV_B64" "$ANVIL_ID" "$B/token")
CODE=$(curl -fsS -o /dev/null -w '%{http_code}' -X POST "$B/token" -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$A_ASSERT")
echo "pending mint http=$CODE (expect 401)"

echo "== human logs in + validates anvil =="
HTOK=$(login "$HUMAN" "$HUMAN_PW")
curl -fsS -H "Authorization: Bearer $HTOK" -X POST "$B/api/agents/$ANVIL_ID/validate" >/dev/null && echo "validated"

echo "== validated anvil mints + token verifies =="
A_ASSERT2=$(go run ./cmd/herald-keytool 2>/dev/null assert "$ANVIL_PRIV_B64" "$ANVIL_ID" "$B/token")
ATOK=$(curl -fsS -X POST "$B/token" -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$A_ASSERT2" | jqr access_token)
[ -n "$ATOK" ] || { echo "FAIL: validated anvil could not mint"; exit 1; }
echo "anvil token=${ATOK:0:24}..."
echo "claims:"; echo "$ATOK" | cut -d. -f2 | tr '_-' '/+' | python3 -c "import sys,base64,json; s=sys.stdin.read().strip(); s+='='*(-len(s)%4); print(json.dumps(json.loads(base64.b64decode(s)),indent=2))"
echo "== DoD PASS: cwadmin->org->human->bootstrap->self-provision->pending->validate->mint =="
