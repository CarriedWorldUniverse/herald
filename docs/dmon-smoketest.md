# herald — running it + the end-to-end smoke (DoD)

herald is a single Go binary. It needs an admin token and (for prod) a
persistent signing key; everything else has sane defaults.

## Run

```bash
go build -o herald ./cmd/herald

HERALD_ADDR=:8099 \
HERALD_DB=/var/lib/nexus/herald.db \
HERALD_ISSUER=https://herald.example/ \
HERALD_ADMIN_TOKEN="$(openssl rand -hex 32)" \
./herald
# On first boot with no HERALD_SIGNING_KEY, herald logs a generated key —
# copy it into HERALD_SIGNING_KEY to persist tokens across restarts.
```

### Config (env)

| var | default | notes |
|-----|---------|-------|
| `HERALD_ADDR` | `:8099` | listen address |
| `HERALD_DB` | `/var/lib/nexus/herald.db` | sqlite path; `:memory:` for tests |
| `HERALD_ISSUER` | `http://<addr>/` | **set to the externally-reachable https URL in prod** — it's the `iss` claim consumers check |
| `HERALD_ADMIN_TOKEN` | — | **required**; gates the bootstrap endpoints |
| `HERALD_SIGNING_KEY` | generated | base64(std) Ed25519 private key. If unset, an ephemeral key is generated and logged — **dev only**; tokens won't survive a restart. Persist in prod. |

## Endpoints

- `GET /healthz`
- `GET /.well-known/openid-configuration` · `GET /jwks` — OIDC discovery + public keys
- `POST /token` — RFC 7523 jwt-bearer (agents mint here with a casket-signed assertion)
- `POST /api/orgs` · `POST /api/orgs/{org}/humans` · `POST /api/orgs/{org}/agents` — admin bootstrap (admin token)
- `POST /api/humans/{id}/token` — MVP human-token stand-in (admin token; full login deferred)
- `POST /api/agents` — **self-provision** (herald token + `agent:create` scope; new agent is PENDING)
- `POST /api/agents/{id}/validate` — human validates a pending agent (human token; responsible human only)

## The golden-path smoke (the MVP DoD)

`scripts/smoke.sh` runs the whole loop with **real casket keys** (via
`herald-keytool`):

```
org → human → bootstrap agent → casket-JWT token
   → self-provision "anvil" (PENDING)
   → pending anvil CANNOT mint (401)        ← human-in-the-loop gate
   → human validates anvil
   → anvil mints a token (sub=anvil, act.sub=human, org, scope, agent_fp)
```

Run it:

```bash
HERALD_ADDR=:8099 HERALD_DB=:memory: HERALD_ADMIN_TOKEN=smoke-admin-token \
  HERALD_ISSUER=http://127.0.0.1:8099/ ./herald &
ADMIN=smoke-admin-token bash scripts/smoke.sh   # prints "DoD PASS" on success
```

## herald-keytool

The agent-side helper (seed of the runtime client, NEX-383):

```bash
herald-keytool derive <owner-seed> <agent-slug>   # -> "<pubB64> <privB64>" (casket DeriveAgentKey)
herald-keytool assert <privB64> <agent-id> <token-url>   # -> a signed jwt-bearer assertion
```

## Deploy on dMon

Embedded-mode (MVP): run alongside the broker under `nexus.slice`. SQLite at
`/var/lib/nexus/herald.db`. Persist `HERALD_SIGNING_KEY` + `HERALD_ADMIN_TOKEN`
in `/etc/nexus/herald.env` (0600). A systemd unit mirrors `nexus.service`.

The DoD on dMon: register a live aspect's casket-derived key as a herald agent,
have it mint a token, and verify it from a consumer with `heraldauth` — proving
the same `DeriveAgentKey(owner_seed, slug)` the aspect already uses works as a
herald identity. (Deferred to the dMon-deploy step.)
