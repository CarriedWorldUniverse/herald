# herald MVP Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the herald MVP — a standalone OIDC identity service where humans log in and **agents authenticate by signing a JWT with their casket Ed25519 key**, issuing self-describing JWTs that any CWU service verifies locally via a `heraldauth` Go package.

**Architecture:** Go service on `github.com/zitadel/oidc/v3` (Apache-2.0) for the OAuth2/OIDC protocol + `github.com/CarriedWorldUniverse/casket-go` for agent-key derivation. Small identity store (orgs, users, scope grants) over SQLite for the embedded-on-dMon MVP. Agent auth = RFC 7523 `jwt-bearer` with EdDSA: agent signs an assertion with its Ed25519 private key, herald verifies against the registered public key, issues a short-lived EdDSA-signed access token carrying identity + org + responsible-human + scopes + casket fingerprints. Consumers verify locally against herald's JWKS.

**Tech Stack:** Go 1.22 · `zitadel/oidc/v3` · `casket-go` · SQLite (`modernc.org/sqlite`, CGO-free) · stdlib `crypto/ed25519` · stdlib `net/http`.

**Source of truth:** [`docs/2026-05-30-herald-mvp-spec.md`](../../2026-05-30-herald-mvp-spec.md). This plan implements spec §2 (in-scope) and honors §9 (deferred). Tracked in NEX-376 + NEX-377–381.

---

## Key grounding facts (verified 2026-05-30)

- **casket-go** (`github.com/CarriedWorldUniverse/casket-go`, Go 1.22) exports `DeriveAgentKey(seed []byte, slug string) (ed25519.PrivateKey, ed25519.PublicKey, error)` — HKDF-SHA256, info `"cairn-agent-v1:"+slug`. Returns plain `ed25519` types. **cairn already uses this derivation** → reuse it so agent identities match across cairn + herald.
- Agent auth is **standard EdDSA JWT** — no custom casket signing path needed. casket supplies key *derivation*; signing/verifying is `crypto/ed25519` + a JWT lib.
- **Token shape** (spec §4): agent token has `sub`=agent-uuid, `act.sub`=responsible-human-uuid (herald-stamped, un-spoofable), `org`, `kind`, `scope`, `agent_fp`, `human_fp`.
- **`main` is branch-protected** (PR required, enforce-admins, linear). Every task lands via PR. Required CI status checks get added after Task 1 establishes the workflow.

---

## File structure

```
herald/
  go.mod                          # module github.com/CarriedWorldUniverse/herald
  cmd/herald/main.go              # standalone entrypoint (flags, wire, serve)
  internal/store/                 # identity store (org, user, scope_grant)
    store.go                      #   interface + types
    sqlite.go                     #   sqlite impl
    schema.sql                    #   migrations
    store_test.go
  internal/identity/              # domain logic above the store
    identity.go                   #   create org/user/agent, grant/revoke, block+cascade
    fingerprint.go                #   casket pubkey -> fingerprint
    identity_test.go
  internal/oidc/                  # the OIDC provider (zitadel/oidc wiring)
    provider.go                   #   signing keys, JWKS, discovery, token endpoint
    agent_grant.go                #   RFC 7523 jwt-bearer: verify casket-signed assertion
    claims.go                     #   assemble the spec-§4 token (act, org, scope, fps)
    oidc_test.go
  internal/adminapi/              # admin REST (orgs/users/scopes/block)
    adminapi.go
    adminapi_test.go
  heraldauth/                     # PUBLIC consumer package (importable by cairn/ledger/...)
    heraldauth.go                 #   fetch+cache JWKS, verify JWT, parse claims
    heraldauth_test.go
  .github/workflows/ci.yml        # build + test matrix (mirror nexus)
```

Rationale: `internal/*` keeps service internals private; **`heraldauth/` is the one public surface** consumers import. Store / identity / oidc / adminapi are separate so each is testable in isolation and the embedded-in-nexus split (later) only needs to lift `internal/oidc` + `internal/identity` + `internal/store` behind an in-process constructor.

---

## Task 1: Repo scaffold + CI

**Files:**
- Create: `go.mod`, `cmd/herald/main.go`, `.github/workflows/ci.yml`

- [ ] **Step 1: Init module + deps**

Run:
```bash
cd herald
go mod init github.com/CarriedWorldUniverse/herald
go get github.com/zitadel/oidc/v3@latest
go get github.com/CarriedWorldUniverse/casket-go@latest
go get modernc.org/sqlite@latest
```

- [ ] **Step 2: Minimal main that builds + serves /healthz**

```go
// cmd/herald/main.go
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("HERALD_ADDR")
	if addr == "" {
		addr = ":8099"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"herald"}`))
	})
	log.Printf("herald listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
```

- [ ] **Step 3: CI workflow mirroring nexus**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
jobs:
  build-test:
    name: build + test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.22' }
      - run: go build ./...
      - run: go test ./...
      - run: go vet ./...
```

- [ ] **Step 4: Verify build + run**

Run: `go build ./... && go vet ./...`
Expected: builds clean.

- [ ] **Step 5: Commit + PR**

```bash
git checkout -b scaffold
git add go.mod go.sum cmd .github
git commit -m "scaffold: herald module + healthz + CI matrix"
git push -u origin scaffold
gh pr create --base main --title "scaffold: herald module + CI" --body "Module init, healthz, 3-platform CI. First PR establishes the build+test checks for branch protection."
```

- [ ] **Step 6: After CI passes + merge — add required status checks**

```bash
# Once the "build + test (...)" checks have reported once, enforce them:
gh api -X PATCH repos/CarriedWorldUniverse/herald/branches/main/protection/required_status_checks \
  -f 'contexts[]=build + test (ubuntu-latest)' \
  -f 'contexts[]=build + test (macos-latest)' \
  -f 'contexts[]=build + test (windows-latest)'
```

---

## Task 2: Identity store (org, user, scope_grant)

**Files:**
- Create: `internal/store/schema.sql`, `internal/store/store.go`, `internal/store/sqlite.go`, `internal/store/store_test.go`

- [ ] **Step 1: Write the schema** (`schema.sql`) — mirrors spec §3

```sql
CREATE TABLE IF NOT EXISTS org (
  id          TEXT PRIMARY KEY,           -- uuid
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',   -- active|blocked
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS user (
  id                 TEXT PRIMARY KEY,    -- uuid = canonical entity id
  org_id             TEXT NOT NULL REFERENCES org(id),
  kind               TEXT NOT NULL,       -- human|agent
  display_name       TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'active',  -- active|blocked
  login_secret       TEXT,                -- human only (hash); null for agent
  casket_pubkey      BLOB,                -- agent only (ed25519 pubkey)
  casket_fingerprint TEXT,               -- agent only
  responsible_human  TEXT REFERENCES user(id),  -- agent only
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_user_org ON user(org_id);
CREATE INDEX IF NOT EXISTS idx_user_responsible ON user(responsible_human);
CREATE TABLE IF NOT EXISTS scope_grant (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES user(id),
  scope      TEXT NOT NULL,
  granted_by TEXT REFERENCES user(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, scope)
);
```

- [ ] **Step 2: Write the failing store test** (`store_test.go`)

```go
func TestSQLite_CreateOrgAndUser(t *testing.T) {
	s := newTestStore(t) // opens :memory: + applies schema
	ctx := context.Background()
	org, err := s.CreateOrg(ctx, "acme")
	if err != nil { t.Fatal(err) }
	h, err := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: "human", DisplayName: "jacinta"})
	if err != nil { t.Fatal(err) }
	if h.ID == "" || h.Kind != "human" { t.Fatalf("bad human: %+v", h) }
	got, err := s.GetUser(ctx, h.ID)
	if err != nil || got.ID != h.ID { t.Fatalf("roundtrip: %v %+v", err, got) }
}

func TestSQLite_AgentCarriesResponsibleHuman(t *testing.T) {
	s := newTestStore(t); ctx := context.Background()
	org, _ := s.CreateOrg(ctx, "acme")
	h, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: "human", DisplayName: "jacinta"})
	a, err := s.CreateUser(ctx, store.User{
		OrgID: org.ID, Kind: "agent", DisplayName: "anvil",
		CasketPubkey: []byte("pub"), CasketFingerprint: "fp", ResponsibleHuman: h.ID,
	})
	if err != nil { t.Fatal(err) }
	if a.ResponsibleHuman != h.ID { t.Fatalf("agent must carry responsible human, got %q", a.ResponsibleHuman) }
}
```

- [ ] **Step 3: Run — expect FAIL** (`store` package doesn't exist). Run: `go test ./internal/store/ -run TestSQLite -v`

- [ ] **Step 4: Implement `store.go` (interface + types) and `sqlite.go`**

Define `Store` interface: `CreateOrg`, `GetOrg`, `CreateUser`, `GetUser`, `GetUserByCasketFingerprint`, `ListAgentsByResponsibleHuman`, `GrantScope`, `RevokeScope`, `ListScopes`, `SetStatus`. `Open(path string) (*SQLite, error)` applies `schema.sql` (embedded via `//go:embed`). UUIDs via `github.com/google/uuid` (add dep). `newTestStore` opens `Open(":memory:")`.

- [ ] **Step 5: Run — expect PASS.** Run: `go test ./internal/store/ -v`

- [ ] **Step 6: Commit + PR** (`feat(store): identity store on sqlite`)

---

## Task 3: Identity domain logic (create agent, fingerprint, block+cascade)

**Files:**
- Create: `internal/identity/fingerprint.go`, `internal/identity/identity.go`, `internal/identity/identity_test.go`

- [ ] **Step 1: Failing fingerprint test**

```go
func TestFingerprint_StableAndShort(t *testing.T) {
	_, pub, err := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	if err != nil { t.Fatal(err) }
	fp := identity.Fingerprint(pub)
	if fp == "" { t.Fatal("empty fingerprint") }
	if identity.Fingerprint(pub) != fp { t.Fatal("fingerprint not stable") }
}
```

- [ ] **Step 2: Run — expect FAIL.** `go test ./internal/identity/ -run TestFingerprint -v`

- [ ] **Step 3: Implement `Fingerprint`** — `base64url(sha256(pubkey))[:N]` (match casket's fingerprint convention if one exists in WIRE.md; otherwise document this as herald's).

- [ ] **Step 4: Failing cascade test**

```go
func TestBlockHuman_CascadesToAgents(t *testing.T) {
	svc := newTestIdentity(t); ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, somePubkey)
	if err := svc.BlockUser(ctx, h.ID); err != nil { t.Fatal(err) }
	// agent must be treated as blocked because its responsible human is blocked
	if svc.IsActive(ctx, a.ID) { t.Fatal("blocking human must cascade to agent") }
}
```

- [ ] **Step 5: Run — expect FAIL.**

- [ ] **Step 6: Implement `identity.go`** — `Service` wrapping `store.Store`. `CreateHuman`, `CreateAgent` (validates responsible_human exists + same org, computes fingerprint), `GrantScope`/`RevokeScope`, `BlockUser`/`UnblockUser`, `IsActive(id)` (returns false if the user is blocked **or** the user is an agent whose responsible_human is blocked — the one-level cascade per spec §9), `EffectiveScopes(id)`.

- [ ] **Step 7: Run — expect PASS.** `go test ./internal/identity/ -v`

- [ ] **Step 8: Commit + PR** (`feat(identity): agent creation, fingerprint, block cascade`)

---

## Task 4: OIDC core — signing, JWKS, discovery (the protocol spine)

**Files:**
- Create: `internal/oidc/provider.go`, `internal/oidc/oidc_test.go`

- [ ] **Step 1: Failing test — JWKS serves a verifiable EdDSA key**

```go
func TestProvider_JWKSHasEdDSAKey(t *testing.T) {
	p := newTestProvider(t) // generates an ed25519 signing key
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/jwks")
	if err != nil || resp.StatusCode != 200 { t.Fatalf("jwks: %v %d", err, resp.StatusCode) }
	var jwks struct{ Keys []map[string]any `json:"keys"` }
	json.NewDecoder(resp.Body).Decode(&jwks)
	if len(jwks.Keys) == 0 || jwks.Keys[0]["kty"] != "OKP" { t.Fatalf("expected OKP/EdDSA key, got %+v", jwks.Keys) }
}
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement `provider.go`** — herald's signing key is **EdDSA (Ed25519)** to match the agent-key world. Wire `zitadel/oidc/v3` op storage (or a thin custom OP if the full storage interface is heavier than MVP needs — prefer the minimal path that gives discovery + JWKS + a token endpoint we control). Expose `/.well-known/openid-configuration`, `/jwks`. `Handler() http.Handler`.

NOTE for the implementer: evaluate in this step whether `zitadel/oidc`'s full `op.Storage` is worth implementing for MVP, or whether we use its JWT/JWKS primitives (`github.com/zitadel/oidc/v3/pkg/oidc` + `crypto`) and hand-roll the two endpoints we need. Decide by which is less code for {discovery, jwks, jwt-bearer token, EdDSA}. Document the choice in the PR.

- [ ] **Step 4: Run — expect PASS.** `go test ./internal/oidc/ -v`

- [ ] **Step 5: Commit + PR** (`feat(oidc): EdDSA signing + JWKS + discovery`)

---

## Task 5: Agent auth — RFC 7523 jwt-bearer with casket verification (THE MAKE-OR-BREAK)

**Files:**
- Create: `internal/oidc/agent_grant.go`, `internal/oidc/claims.go`; extend `oidc_test.go`

- [ ] **Step 1: Failing end-to-end test — an agent mints a token with a casket key**

```go
func TestAgentGrant_CasketSignedAssertion_IssuesToken(t *testing.T) {
	svc := newTestIdentity(t); ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)

	p := newTestProviderWith(t, svc)
	srv := httptest.NewServer(p.Handler()); defer srv.Close()

	// Agent builds a signed assertion (iss=sub=agent id, aud=token endpoint, short exp), EdDSA.
	assertion := signAgentAssertion(t, a.ID, srv.URL+"/token", priv)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	resp, _ := http.PostForm(srv.URL+"/token", form)
	if resp.StatusCode != 200 { t.Fatalf("token endpoint: %d", resp.StatusCode) }

	var tok struct{ AccessToken string `json:"access_token"` }
	json.NewDecoder(resp.Body).Decode(&tok)

	// Verify the issued token against herald's JWKS and check claims.
	claims := verifyAgainstJWKS(t, srv.URL, tok.AccessToken)
	if claims["sub"] != a.ID { t.Fatalf("sub: %v", claims["sub"]) }
	if act, _ := claims["act"].(map[string]any); act["sub"] != h.ID {
		t.Fatalf("act.sub must be responsible human, got %v", act)
	}
	if claims["org"] != org.ID { t.Fatalf("org: %v", claims["org"]) }
	if !strings.Contains(claims["scope"].(string), "repo:write") { t.Fatalf("scope: %v", claims["scope"]) }
}
```

- [ ] **Step 2: Failing negative tests** — (a) assertion signed by a *different* key than registered → 401; (b) agent whose responsible human is blocked → 401; (c) agent cannot set its own `act` (herald stamps it from the record, ignoring any client-supplied human).

- [ ] **Step 3: Run — expect FAIL.**

- [ ] **Step 4: Implement `agent_grant.go`** — parse the `jwt-bearer` assertion, extract the agent id (`sub`), load the agent from identity, **verify the assertion signature with the registered Ed25519 pubkey** (`ed25519.Verify`), check `IsActive` (cascade), validate `aud`/`exp`/`iss==sub`. On success call `claims.Assemble`.

- [ ] **Step 5: Implement `claims.go`** — build the spec-§4 token: `sub`=agent, `act.sub`=`agent.ResponsibleHuman` (**from the record, never the client**), `org`, `kind`, `scope`=space-joined `EffectiveScopes`, `agent_fp`, `human_fp` (if the human has a casket id), standard `iss/iat/exp/jti`. Sign EdDSA with herald's key.

- [ ] **Step 6: Run — expect PASS** (all of Step 1 + Step 2). `go test ./internal/oidc/ -v`

- [ ] **Step 7: Commit + PR** (`feat(oidc): casket jwt-bearer agent auth + token claims`) — **this PR is the make-or-break milestone.**

---

## Task 6: heraldauth — the consumer verification package (the payoff)

**Files:**
- Create: `heraldauth/heraldauth.go`, `heraldauth/heraldauth_test.go`

- [ ] **Step 1: Failing test — verify a herald token locally, parse identity**

```go
func TestVerifier_AcceptsValidToken_ParsesClaims(t *testing.T) {
	// Spin a herald, mint an agent token (reuse Task 5 helpers), then:
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: heraldURL})
	if err != nil { t.Fatal(err) }
	id, err := v.Verify(ctx, agentToken)
	if err != nil { t.Fatal(err) }
	if id.Subject != agentID || id.Kind != "agent" { t.Fatalf("%+v", id) }
	if id.ResponsibleHuman != humanID { t.Fatal("must expose responsible human") }
	if !id.HasScope("repo:write") { t.Fatal("scope check") }
	if id.Org != orgID { t.Fatal("org") }
}

func TestVerifier_RejectsTamperedToken(t *testing.T) { /* flip a byte -> error */ }
func TestVerifier_RejectsWrongIssuer(t *testing.T)  { /* aud/iss mismatch -> error */ }
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement `heraldauth.go`** — `New(ctx, Config{Issuer})` fetches discovery + JWKS (cached, background refresh on rotation). `Verify(ctx, token) (Identity, error)` validates signature/iss/aud/exp locally (no network per call after JWKS cached). `Identity{Subject, Kind, Org, ResponsibleHuman, Scopes, AgentFP, HumanFP}` with `HasScope(s)`. This is the package cairn/ledger/porter/knowledge/comms import.

- [ ] **Step 4: Run — expect PASS.** `go test ./heraldauth/ -v`

- [ ] **Step 5: Worked example** — add `heraldauth/example_test.go` (an `ExampleVerifier` gating a dummy `http.Handler` on `repo:write`) so consumers have copy-paste integration.

- [ ] **Step 6: Commit + PR** (`feat(heraldauth): local JWKS verification consumer package`)

---

## Task 7: Human login + admin API

**Files:**
- Create: `internal/adminapi/adminapi.go`, `internal/adminapi/adminapi_test.go`; extend `internal/oidc` for human login.

- [ ] **Step 1: Failing admin-API tests** — `POST /api/orgs`, `POST /api/orgs/{id}/users` (human + agent variants; agent body carries base64 casket pubkey + responsible_human), `POST /api/users/{id}/scopes`, `POST /api/users/{id}/block` (then assert the agent token path rejects). Gated by a static `HERALD_ADMIN_TOKEN` bearer for MVP.

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement `adminapi.go`** per spec §7. Admin-token middleware.

- [ ] **Step 4: Human login (v0)** — implement the simplest spec-§5b path that yields a `kind:human` token (password against `login_secret`, or `zitadel/oidc` auth-code if cheaper). Passkey is preferred but **acceptable to stub to password for MVP** — document the choice.

- [ ] **Step 5: Run — expect PASS.** `go test ./internal/adminapi/ -v`

- [ ] **Step 6: Commit + PR** (`feat(adminapi): orgs/users/scopes/block + human login`)

---

## Task 8: Wire it together + dMon end-to-end (Definition of Done)

**Files:**
- Modify: `cmd/herald/main.go` (wire store + identity + oidc + adminapi, flags: `HERALD_ADDR`, `HERALD_DB`, `HERALD_ADMIN_TOKEN`, `HERALD_ISSUER`)
- Create: `docs/dmon-smoketest.md` (the runbook)

- [ ] **Step 1: Wire `main.go`** — open store, build identity service, build OIDC provider + admin API, mount all handlers, serve.

- [ ] **Step 2: Build + run locally**, smoke the full loop with `curl`: create org → create human → create agent (register a real `DeriveAgentKey` pubkey) → grant scope → agent mints token via jwt-bearer → `heraldauth` verifies. Capture in `dmon-smoketest.md`.

- [ ] **Step 3: Deploy to dMon** — build, `install` to `/usr/local/bin/herald`, run under a systemd unit in `nexus.slice` (or as a `cmd/herald` for now). SQLite at `/var/lib/nexus/herald.db`.

- [ ] **Step 4: THE DoD TEST — a real dMon aspect authenticates.** Take a live aspect's casket-derived key (the same `DeriveAgentKey(owner_seed, slug)` the aspect already uses), register it as a herald agent under an org with a responsible human + a scope; have a tiny consumer (or `heraldauth` test binary) verify a token the aspect mints and enforce the scope. **End to end: aspect → herald token (identity + org + responsible-human + scope) → consumer verifies locally → scope enforced.**

- [ ] **Step 5: Commit + PR** (`feat: wire herald service + dMon e2e runbook`). Update NEX-376 with the DoD result.

---

## Self-review checklist (run before calling MVP done)

- [ ] Every spec §2 in-scope item has a task. Nothing from spec §9 (deferred) leaked in.
- [ ] Agent token's `act.sub` is **always** herald-stamped from the record — no client path can set it (Task 5 Step 2c proves it).
- [ ] `heraldauth.Verify` makes **no network call per request** after JWKS is cached (Task 6).
- [ ] Block-human cascade is enforced at the token-issuance path, not just the store (Task 5 negative test).
- [ ] EdDSA used end to end (herald signing key + agent keys) — consistent with casket's Ed25519.
- [ ] `heraldauth` is the **only** package a consumer needs to import.

## Open decisions resolved during build (document in the relevant PR)

- SQLite vs Postgres → **SQLite** for embedded dMon MVP (spec §11); revisit for standalone.
- `jwt-bearer` vs client-credentials → **jwt-bearer** (Task 5) unless the implementer finds client-credentials cleaner in `zitadel/oidc`.
- Full `zitadel/oidc` `op.Storage` vs minimal hand-rolled endpoints → decided in Task 4 Step 3.
- Scope vocabulary → agree a starter set with consumers (cairn/ledger/porter/knowledge/comms) before Task 7; seed: `repo:{read,write,create}`, `issue:{read,claim,comment,transition}`, `store:{read,write}`, `comms:{read,post}`, `knowledge:{read,write}`.
