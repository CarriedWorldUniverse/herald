# herald — running it + the end-to-end smoke (DoD)

herald is a single Go binary. Org/human/agent admin is the gRPC AdminService
behind interchange (authority is derived from a herald JWT carrying
`herald:platform-admin` / `herald:org-admin`); the admin org + its owner
(`cwadmin@carriedworld.com`) are seeded at deploy time from
`HERALD_GENESIS_OWNER_PASSWORD`. For prod, also persist a signing key.

## Run

```bash
go build -o herald ./cmd/herald

HERALD_ADDR=:8099 \
HERALD_DB=/var/lib/nexus/herald.db \
HERALD_ISSUER=https://herald.example/ \
HERALD_GENESIS_OWNER_PASSWORD="$(openssl rand -hex 16)" \
HERALD_DEV_INSECURE=1 \
./herald
# HERALD_DEV_INSECURE=1 starts the gRPC admin without mTLS (dev only); in prod
# set HERALD_TLS_CERT/_KEY/_CA instead. On first boot with no HERALD_SIGNING_KEY,
# herald logs a generated key — copy it into HERALD_SIGNING_KEY to persist
# tokens across restarts.
```

### Config (env)

| var | default | notes |
|-----|---------|-------|
| `HERALD_ADDR` | `:8099` | HTTP listen address (OIDC + token-authed provision API) |
| `HERALD_GRPC_ADDR` | `:8098` | gRPC admin/internal API (starts only with TLS certs or `HERALD_DEV_INSECURE=1`) |
| `HERALD_DB` | `/var/lib/nexus/herald.db` | sqlite path; `:memory:` for tests |
| `HERALD_ISSUER` | `http://<addr>/` | **set to the externally-reachable https URL in prod** — it's the `iss` claim consumers check |
| `HERALD_GENESIS_OWNER_PASSWORD` | — | seeds the admin-org owner `cwadmin@carriedworld.com`. No default account/password ships in the image. |
| `HERALD_TLS_CERT` / `_KEY` / `_CA` | — | mTLS for the gRPC admin (vs the cwb-ca). Omit + set `HERALD_DEV_INSECURE=1` for local dev. |
| `HERALD_SIGNING_KEY` | generated | base64(std) Ed25519 private key. If unset, an ephemeral key is generated and logged — **dev only**; tokens won't survive a restart. Persist in prod. |

## Endpoints

HTTP (port `HERALD_ADDR`):

- `GET /healthz`
- `GET /.well-known/openid-configuration` · `GET /jwks` — OIDC discovery + public keys
- `POST /token` — RFC 7523 jwt-bearer (agents mint with a casket-signed assertion) + the `password` grant (human login, by id / email / display name)
- `POST /api/agents` — **self-provision** (herald token + `agent:create` scope; new agent is PENDING)
- `POST /api/agents/{id}/validate` — human validates a pending agent (human token; responsible human only)
- `GET /api/agents/by-fingerprint/{fp}` — in-cluster service lookup (cairn's SSH ingress; cairn now prefers the gRPC AgentService over mTLS)

gRPC AdminService (port `HERALD_GRPC_ADDR`, mTLS, fronted by interchange) —
identity-derived authz, no static token: CreateOrg / ListOrgs / DeleteOrg /
CreateHuman / CreateAgent / SetHumanPassword / IssueHumanToken / products
get·enable·disable.

## The golden-path smoke (the MVP DoD)

The comprehensive end-to-end DoD is the **cwb-conformance** suite
(`cwb-conform -target dmon -layers all`), which exercises every pillar through
the gateway. For a quick local loop, `scripts/smoke.sh` runs the herald slice
with **real casket keys** (via `herald-keytool`), driving admin provisioning
through the gateway as the `cwadmin` owner:

```
cwadmin login → org → human → bootstrap agent → casket-JWT token
   → self-provision "anvil" (PENDING)
   → pending anvil CANNOT mint (401)        ← human-in-the-loop gate
   → human logs in + validates anvil
   → anvil mints a token (sub=anvil, act.sub=human, org, scope, agent_fp)
```

Run it against a gateway (interchange + herald up):

```bash
GATEWAY=http://127.0.0.1:8080 \
OWNER_PASSWORD="<genesis owner password>" \
  bash scripts/smoke.sh   # prints "DoD PASS" on success
```

## herald-keytool

The agent-side helper (seed of the runtime client, NEX-383):

```bash
herald-keytool derive <owner-seed> <agent-slug>   # -> "<pubB64> <privB64>" (casket DeriveAgentKey)
herald-keytool assert <privB64> <agent-id> <token-url>   # -> a signed jwt-bearer assertion
```

## Deploy on dMon

Embedded-mode (MVP): run alongside the broker under `nexus.slice`. SQLite at
`/var/lib/nexus/herald.db`. Persist `HERALD_SIGNING_KEY` +
`HERALD_GENESIS_OWNER_PASSWORD` in `/etc/nexus/herald.env` (0600). A systemd
unit mirrors `nexus.service`.

The DoD on dMon: register a live aspect's casket-derived key as a herald agent,
have it mint a token, and verify it from a consumer with `heraldauth` — proving
the same `DeriveAgentKey(owner_seed, slug)` the aspect already uses works as a
herald identity. (Deferred to the dMon-deploy step.)
