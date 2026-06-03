# herald `GET /api/me` Implementation Plan (#7a)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is a MULTI-REPO change (cwb-proto → herald → interchange → cwb-conformance → deploy); cross-repo version pinning + the dMon deploy are CONTROLLER steps between tasks (noted inline).

**Goal:** Add a `Me` RPC (`GET /api/me`) to herald's AdminService returning the caller's own authoritative identity record, exposed through interchange, conformance-verified, deployed to dMon.

**Architecture:** New AdminService RPC, identity-derived authz (no admin scope), served by the identity service which already has the full record. Standard proto→herald→interchange mesh flow. Spec: `herald/docs/superpowers/specs/2026-06-03-herald-me-endpoint-design.md`.

**Tech Stack:** Go 1.26, buf (cwb-proto), grpc-gateway, k3s on dMon.

## Verified mechanics (from the repos)

- **cwb-proto**: `buf generate` (config `buf.gen.yaml`); generated Go is COMMITTED under `gen/go/cwb/herald/v1/{herald.pb.go,herald_grpc.pb.go,herald.pb.gw.go}` and a CI drift-check (`buf.yml`) enforces it. `option go_package = "...gen/go/cwb/herald/v1;heraldv1"`. Proto: `proto/cwb/herald/v1/herald.proto`.
- **Pinning**: pseudo-versions (`v0.0.0-<date>-<hash>`), bumped downstream via `go get <mod>@<hash>`. **Pin to the MERGED-MAIN commit** (a squash-merge orphans branch-commit hashes). herald import alias `heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"` (`internal/grpcadmin/admin.go`).
- **interchange**: registers the herald gateway at `cmd/interchange-gateway/main.go` via `heraldv1.RegisterAdminServiceHandler(...)` — generic, so adding `Me` needs only a cwb-proto bump + rebuild (the 501-until-rebuilt gotcha). go.mod pins cwb-proto.
- **herald handler deps**: `adminServer{ s *Servers }`; `a.s.id` (the `Identity` interface) ALREADY exposes `GetUser`/`GetOrg`/`EffectiveScopes`/`callerFromCtx` — no widening. `store.User{ID,OrgID,Kind,DisplayName,Status,ResponsibleHuman,CasketFingerprint}` (Kind/Status typed → `string(...)`); `store.Org{Name}`.
- **deploy (dMon, namespace `cwb`)**: `podman build -f cmd/<svc>/Containerfile -t <svc>:dev . && podman save <svc>:dev | sudo k3s ctr images import - && kubectl rollout restart deployment/<svc> -n cwb` for `herald` and `interchange-gateway`. Conformance: `cwb-conform -target dmon -layers all` (`all` is a sole keyword).

---

## Task 1: cwb-proto — add the `Me` RPC + messages

**Repo:** `/Users/jacinta/Source/cwb-proto` (branch `nex-herald-me`)
**Files:** `proto/cwb/herald/v1/herald.proto`, regenerated `gen/go/cwb/herald/v1/*`

- [ ] **Step 1: Add the RPC to `service AdminService`** in `proto/cwb/herald/v1/herald.proto` (place after the last existing RPC, before the closing `}`):

```protobuf
  // Me — the caller's own authoritative identity record. Any AUTHENTICATED
  // principal (no admin scope); identity-derived from the verified subject.
  rpc Me(MeRequest) returns (MeResponse) {
    option (google.api.http) = {
      get: "/api/me"
      response_body: "user"
    };
  }
```

- [ ] **Step 2: Add the messages** (after the existing message block):

```protobuf
message MeRequest {}
message MeResponse {
  UserInfo user = 1;
}
// UserInfo is a caller's own authoritative identity (agent fields empty for humans).
message UserInfo {
  string id = 1;
  string kind = 2;               // "human" | "agent"
  string display_name = 3;
  string org = 4;                // org id
  string org_name = 5;           // enriched via GetOrg
  string status = 6;             // "active" | "blocked" | "pending"
  repeated string scopes = 7;    // authoritative (store-current) scopes
  string responsible_human = 8;  // agent only
  string fingerprint = 9;        // agent only (casket)
}
```

- [ ] **Step 3: Regenerate** — `cd /Users/jacinta/Source/cwb-proto && buf generate`

If `buf` is not installed, STOP and report `STATUS: BLOCKED` (the controller will install buf / run gen) — do NOT hand-edit the generated files. Expected: `git status` shows modified `gen/go/cwb/herald/v1/herald.pb.go`, `herald_grpc.pb.go`, `herald.pb.gw.go` containing `Me`/`MeRequest`/`MeResponse`/`UserInfo` + a `/api/me` pattern in the `.pb.gw.go`.

- [ ] **Step 4: Verify it compiles + no stray drift** — `cd /Users/jacinta/Source/cwb-proto && go build ./... && git diff --stat gen/`
Expected: builds; the only gen changes are herald/v1 (no unrelated drift).

- [ ] **Step 5: Commit**

```bash
cd /Users/jacinta/Source/cwb-proto && git add proto/cwb/herald/v1/herald.proto gen/go/cwb/herald/v1/
git commit -m "herald.v1: add Me RPC (GET /api/me) for server-authoritative whoami"
```

> **CONTROLLER (between Task 1 and Task 2):** push the cwb-proto branch, open + **merge** the cwb-proto PR to main (squash), capture the **merged-main** short hash `H` (`git -C ../cwb-proto fetch && git -C ../cwb-proto rev-parse --short origin/main`). Provide `H` to Task 2 + Task 3 (and Task 4 if it imports cwb-proto). All downstream pins use `cwb-proto@H` where `H` is the merged-main commit.

---

## Task 2: herald — implement `Me`

**Repo:** `/Users/jacinta/Source/herald` (branch `nex-herald-me`)
**Files:** `go.mod`/`go.sum` (bump), `internal/grpcadmin/admin.go`, `internal/grpcadmin/<me_test or admin_test>.go`

- [ ] **Step 1: Pin the new proto** — `cd /Users/jacinta/Source/herald && go get github.com/CarriedWorldUniverse/cwb-proto@<H> && go mod tidy`
(`<H>` = the merged-main cwb-proto hash from the controller.) Expected: go.mod's cwb-proto pseudo-version updates; `go build ./...` now sees `heraldv1.MeRequest`/`MeResponse`/`UserInfo` + the `UnimplementedAdminServiceServer` gains `Me`.

- [ ] **Step 2: Write the failing unit test** in `internal/grpcadmin/me_test.go`. Mirror the existing `grpcadmin_test.go` dial/metadata helpers (read them first — they inject `cwb-*` metadata for a verified caller and provision via the in-process server). The test: provision a human + an agent, then call `Me` as each (inject their subject as `cwb-subject`), asserting the returned `UserInfo`:

```go
package grpcadmin

import (
	"context"
	"testing"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"google.golang.org/grpc/metadata"
)

func TestMe(t *testing.T) {
	// Reuse the package's existing in-process harness: a real Identity service +
	// an adminServer. Follow grpcadmin_test.go for how it builds `id`/the server
	// and provisions an org/human/agent. Adapt names to the existing helpers.
	id := newID(t)                          // existing helper (identity service over a temp store)
	srv := &adminServer{s: New(id, nil, nil)} // match how grpcadmin_test.go constructs the server

	ctx := context.Background()
	org, err := id.CreateOrg(ctx, "acme")
	if err != nil { t.Fatal(err) }
	human, err := id.CreateHuman(ctx, org.ID, "alice@x")
	if err != nil { t.Fatal(err) }
	if err := id.GrantScope(ctx, human.ID, "issue:read", human.ID); err != nil { t.Fatal(err) }

	// Me as the human (subject injected as interchange would).
	hctx := metadata.NewIncomingContext(ctx, metadata.Pairs("cwb-subject", human.ID, "cwb-org", org.ID))
	resp, err := srv.Me(hctx, &heraldv1.MeRequest{})
	if err != nil { t.Fatalf("Me(human): %v", err) }
	u := resp.User
	if u.Id != human.ID || u.Kind != "human" || u.Org != org.ID || u.OrgName != "acme" || u.Status != "active" {
		t.Fatalf("human UserInfo: %+v", u)
	}
	if u.ResponsibleHuman != "" || u.Fingerprint != "" {
		t.Fatalf("human should have no agent fields: %+v", u)
	}
	hasScope := false
	for _, s := range u.Scopes { if s == "issue:read" { hasScope = true } }
	if !hasScope { t.Fatalf("human scopes missing issue:read: %v", u.Scopes) }

	// Me with no verified subject → Unauthenticated.
	if _, err := srv.Me(ctx, &heraldv1.MeRequest{}); err == nil {
		t.Fatal("Me without cwb-subject should be Unauthenticated")
	}
}
```

> **Implementer note:** the exact harness constructors (`newID`, how the `adminServer`/`Servers` is built, how an AGENT is provisioned with a pubkey) MUST be copied from `internal/grpcadmin/grpcadmin_test.go` / `admin_test.go` — adapt the snippet above to the real helper names. Add an AGENT sub-case asserting `Kind=="agent"`, `ResponsibleHuman==human.ID`, `Fingerprint!=""` using the same agent-creation path the existing tests use (`id.CreateAgent(ctx, org.ID, "builder", human.ID, pub)`).

- [ ] **Step 3: Run — expect FAIL** — `cd /Users/jacinta/Source/herald && go test ./internal/grpcadmin/ -run TestMe`
Expected: FAIL — `adminServer` has no `Me` method (or `UnimplementedAdminServiceServer.Me` returns Unimplemented).

- [ ] **Step 4: Implement `Me`** in `internal/grpcadmin/admin.go` (alongside the other handlers):

```go
// Me returns the caller's own authoritative identity record. Any authenticated
// principal may call it for themselves — no admin scope (callerFromCtx only).
func (a *adminServer) Me(ctx context.Context, _ *heraldv1.MeRequest) (*heraldv1.MeResponse, error) {
	c, ok := callerFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
	}
	user, err := a.s.id.GetUser(ctx, c.Subject)
	if err != nil {
		return nil, status.Error(codes.NotFound, "identity not found")
	}
	org, err := a.s.id.GetOrg(ctx, user.OrgID)
	if err != nil {
		return nil, status.Error(codes.Internal, "org lookup failed")
	}
	scopes, err := a.s.id.EffectiveScopes(ctx, user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "scope lookup failed")
	}
	return &heraldv1.MeResponse{User: &heraldv1.UserInfo{
		Id:               user.ID,
		Kind:             string(user.Kind),
		DisplayName:      user.DisplayName,
		Org:              user.OrgID,
		OrgName:          org.Name,
		Status:           string(user.Status),
		Scopes:           scopes,
		ResponsibleHuman: user.ResponsibleHuman,
		Fingerprint:      user.CasketFingerprint,
	}}, nil
}
```

(`status`/`codes` are already imported by `admin.go`. Confirm `store.User`/`store.Org` field names against `internal/store/store.go` and adjust if they differ.)

- [ ] **Step 5: Run — expect PASS** — `cd /Users/jacinta/Source/herald && go test ./internal/grpcadmin/ -run TestMe -v && go build ./... && go test ./... && go vet ./...`
Expected: `TestMe` PASS; full herald suite green.

- [ ] **Step 6: Commit**

```bash
cd /Users/jacinta/Source/herald && git add go.mod go.sum internal/grpcadmin/
git commit -m "grpcadmin: implement Me (GET /api/me) — caller's authoritative identity"
```

---

## Task 3: interchange — rebuild against the new proto

**Repo:** `/Users/jacinta/Source/interchange` (branch `nex-herald-me`)
**Files:** `go.mod`/`go.sum`

- [ ] **Step 1: Bump cwb-proto** — `cd /Users/jacinta/Source/interchange && go get github.com/CarriedWorldUniverse/cwb-proto@<H> && go mod tidy`

- [ ] **Step 2: Verify the route compiles in** — `cd /Users/jacinta/Source/interchange && go build ./... && go vet ./...`
Expected: builds clean. The generated `RegisterAdminServiceHandler` now includes the `/api/me` route (no interchange code change needed — confirm `cmd/interchange-gateway/main.go` still calls `heraldv1.RegisterAdminServiceHandler`).

- [ ] **Step 3: Run interchange's tests** — `cd /Users/jacinta/Source/interchange && go test ./...`
Expected: green (no behavior change; the bump just adds a route).

- [ ] **Step 4: Commit**

```bash
cd /Users/jacinta/Source/interchange && git add go.mod go.sum
git commit -m "deps: bump cwb-proto for herald Me (GET /api/me) route"
```

---

## Task 4: cwb-conformance — a `Me` subtest in the herald layer

**Repo:** `/Users/jacinta/Source/cwb-conformance` (branch `nex-herald-me`)
**Files:** `conformance/herald/herald_test.go` (add `testMe` + register it); `go.mod` if it imports cwb-proto types (it decodes JSON directly, so likely NO bump needed — verify).

- [ ] **Step 1: Add the subtest** to `conformance/herald/herald_test.go`, following the existing subtest pattern (read the file: `fixtures.ProvisionOrg`, `wire.Get`, `tgt.HeraldBase()`, the provisioned `org.Humans["alice"]`/`org.Agents["builder"]` principals with `.ID`/`.Token`/`.Scopes`, `org.OrgID`/`org.OrgName`):

```go
func testMe(t *testing.T, tgt *target.Target, org *fixtures.TestOrg) {
	type userInfo struct {
		ID               string   `json:"id"`
		Kind             string   `json:"kind"`
		DisplayName      string   `json:"display_name"`
		Org              string   `json:"org"`
		OrgName          string   `json:"org_name"`
		Status           string   `json:"status"`
		Scopes           []string `json:"scopes"`
		ResponsibleHuman string   `json:"responsible_human"`
		Fingerprint      string   `json:"fingerprint"`
	}
	get := func(t *testing.T, tok string) userInfo {
		t.Helper()
		ctx := context.Background()
		resp, raw, err := wire.Get(ctx, tgt.HeraldBase()+"/api/me", http.Header{"Authorization": {"Bearer " + tok}})
		if err != nil {
			t.Fatalf("GET /api/me: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/me status=%d: %s", resp.StatusCode, raw)
		}
		var ui userInfo
		if err := json.Unmarshal(raw, &ui); err != nil {
			t.Fatalf("decode userinfo: %v (%s)", err, raw)
		}
		return ui
	}

	alice := org.Humans["alice"]
	hu := get(t, alice.Token)
	if hu.ID != alice.ID || hu.Kind != "human" || hu.Org != org.OrgID || hu.OrgName != org.OrgName || hu.Status != "active" {
		t.Fatalf("human /api/me: %+v", hu)
	}
	if hu.ResponsibleHuman != "" || hu.Fingerprint != "" {
		t.Fatalf("human should have no agent fields: %+v", hu)
	}

	builder := org.Agents["builder"]
	ag := get(t, builder.Token)
	if ag.Kind != "agent" || ag.ResponsibleHuman == "" || ag.Fingerprint == "" {
		t.Fatalf("agent /api/me: %+v", ag)
	}
	for _, want := range builder.Scopes {
		found := false
		for _, s := range ag.Scopes {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("agent scopes missing %q (got %v)", want, ag.Scopes)
		}
	}
}
```

> **Implementer note:** match the real fixture field names (`org.Humans`/`org.Agents` map keys, `Principal.Token`/`.ID`/`.Scopes`, `org.OrgName`) against `internal/fixtures/org.go` and the existing subtests — adjust accessors as needed. Ensure the needed imports (`context`, `encoding/json`, `net/http`, the `wire`/`target`/`fixtures` packages) are present.

- [ ] **Step 2: Register it** in `TestHeraldLayer` alongside the other `t.Run(...)` calls:
```go
	t.Run("Me", func(t *testing.T) { testMe(t, tgt, org) })
```

- [ ] **Step 3: Verify it compiles (offline)** — `cd /Users/jacinta/Source/cwb-conformance && go build ./... && go vet ./...`
Expected: builds. (The live assertions only run under `cwb-conform -target dmon`.)

- [ ] **Step 4: Commit**

```bash
cd /Users/jacinta/Source/cwb-conformance && git add conformance/herald/
git commit -m "conformance/herald: assert GET /api/me returns the caller's record (human + agent)"
```

---

## Task 5: CONTROLLER — deploy + conformance + merge (not an implementer task)

The controller (not a subagent) performs the cross-repo release + dMon deploy + verification:

- [ ] Ensure cwb-proto is merged to main (done between Task 1/2); herald, interchange, conformance branches pushed with PRs open.
- [ ] On dMon (ssh): for `herald` and `interchange-gateway`, from each repo's checkout at the PR branch: `podman build -f cmd/<svc>/Containerfile -t <svc>:dev . && podman save <svc>:dev | sudo k3s ctr images import - && kubectl rollout restart deployment/<svc> -n cwb`. Wait for rollout (`kubectl rollout status`).
- [ ] `cwb-conform -target dmon -layers all` (with `CWB_*` runtime env) → GREEN, including the new herald `Me` subtest.
- [ ] Manual smoke: `curl -H "Authorization: Bearer <human-tok>" <edge>/herald/api/me` and `<agent-tok>` → bare `UserInfo` JSON with the right fields (agent shows responsible_human + fingerprint).
- [ ] Merge the herald, interchange, and conformance PRs (squash + delete branch). cwb-proto already merged.

---

## Self-review

**Spec coverage (#7a):**
- cwb-proto `Me` RPC + `UserInfo`/`MeRequest`/`MeResponse` (`response_body:"user"` → bare UserInfo) → Task 1. ✔
- herald `Me` handler (identity-derived authz, GetUser+GetOrg+EffectiveScopes, agent extras) + unit test → Task 2. ✔
- interchange rebuild for the `/api/me` route (the 501 gotcha) → Task 3. ✔
- conformance `Me` subtest (human + agent, asserts record matches provisioned) → Task 4. ✔
- deploy both images to dMon + conformance-green + curl smoke → Task 5 (controller). ✔
- authz: any authenticated caller, own record only (no admin scope) → Task 2 handler (`callerFromCtx`, no `require*Admin`). ✔

**Placeholder scan:** the implementer notes ("match the real harness/fixture helper names") are deliberate — the exact test-harness constructors live in each repo's existing tests and must be copied, not guessed; the handler + proto + subtest bodies are concrete.

**Type consistency:** `heraldv1.{Me,MeRequest,MeResponse,UserInfo}`; herald handler uses `a.s.id.{GetUser,GetOrg,EffectiveScopes}` + `callerFromCtx` (all confirmed on the `Identity` interface) + `store.User`/`store.Org` fields; cw-side (#7b) will mirror the `UserInfo` JSON shape. Pins thread the single merged-main cwb-proto hash `H` through herald + interchange.
