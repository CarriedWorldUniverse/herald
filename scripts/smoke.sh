#!/usr/bin/env bash
# herald end-to-end smoke: the golden-path MVP loop with a REAL casket key.
set -uo pipefail
B="http://127.0.0.1:8099"
ADMIN="smoke-admin-token"
hdr_admin=(-H "Authorization: Bearer $ADMIN")
jqr() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))"; }

echo "== healthz =="; curl -fsS "$B/healthz"; echo
echo "== discovery =="; curl -fsS "$B/.well-known/openid-configuration" | python3 -c "import sys,json;d=json.load(sys.stdin);print('issuer',d['issuer'],'| token_ep',d['token_endpoint'])"
echo "== jwks =="; curl -fsS "$B/jwks" | python3 -c "import sys,json;k=json.load(sys.stdin)['keys'][0];print('kty',k['kty'],'crv',k['crv'],'kid',k['kid'])"

echo "== create org =="
ORG=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/orgs" -d '{"name":"acme"}' | jqr id); echo "org=$ORG"
echo "== create human =="
HUMAN=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/orgs/$ORG/humans" -d '{"display_name":"jacinta"}' | jqr id); echo "human=$HUMAN"

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

echo "== human validates anvil =="
HTOK=$(curl -fsS "${hdr_admin[@]}" -X POST "$B/api/humans/$HUMAN/token" | jqr access_token)
curl -fsS -H "Authorization: Bearer $HTOK" -X POST "$B/api/agents/$ANVIL_ID/validate" >/dev/null && echo "validated"

echo "== validated anvil mints + token verifies =="
A_ASSERT2=$(go run ./cmd/herald-keytool 2>/dev/null assert "$ANVIL_PRIV_B64" "$ANVIL_ID" "$B/token")
ATOK=$(curl -fsS -X POST "$B/token" -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=$A_ASSERT2" | jqr access_token)
[ -n "$ATOK" ] || { echo "FAIL: validated anvil could not mint"; exit 1; }
echo "anvil token=${ATOK:0:24}..."
echo "claims:"; echo "$ATOK" | cut -d. -f2 | tr '_-' '/+' | python3 -c "import sys,base64,json; s=sys.stdin.read().strip(); s+='='*(-len(s)%4); print(json.dumps(json.loads(base64.b64decode(s)),indent=2))"
echo "== DoD PASS: org->human->bootstrap->self-provision->pending->validate->mint =="
