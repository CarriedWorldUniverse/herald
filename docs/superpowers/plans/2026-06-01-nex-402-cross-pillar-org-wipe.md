# NEX-402 Cross-Pillar Org Wipe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `DELETE /api/orgs/{id}` on herald (admin token + confirm-by-name) wipes an org across all four pillars — herald identity, cairn repos, ledger issues, commonplace knowledge — by minting an `org:purge` token and calling each pillar's self-org purge through the interchange gateway, strict (herald identity deleted only after all pillars succeed).

**Architecture:** herald orchestrates. It self-signs a short-lived token `{org:id, scope:"org:purge", products:[all]}` and calls each pillar's `DELETE /api/org` THROUGH the gateway (which verifies + injects `X-CWB-Org`); each pillar purges its own auth-bound org (no foreign org in any path). herald deletes its own rows last, in a transaction with deferred FK checks. Pillar purges are idempotent no-ops on empty data, so the operation is safely retryable.

**Tech Stack:** Go, SQLite (modernc), go-jose (herald token signing via existing `provider.SignToken`), `net/http`.

**Spec:** `docs/2026-06-01-nex-402-cross-pillar-org-wipe-spec.md`

**Repos & branches:**
- Tasks 1–4: **herald** (`/Users/jacinta/Source/herald`), branch `feat/nex-402-org-wipe` (already checked out).
- Task 5: **cairn** (`/Users/jacinta/Source/cairn`), new branch `feat/nex-402-org-purge`.
- Task 6: **commonplace** (`/Users/jacinta/Source/commonplace`), new branch `feat/nex-402-org-purge`.
- Task 7: **ledger** (`/Users/jacinta/Source/ledger`), new branch `feat/nex-402-org-purge`.
- Task 8: **cwb-conformance** (`/Users/jacinta/Source/cwb-conformance`), new branch `feat/nex-402-reap`.
- Task 9: deploy/ops (controller; SSH to dMon). "Verification" replaces unit tests there.

**Cross-cutting contract (all pillars):** the purge route is `DELETE /api/org` (no path param). It operates ONLY on the caller's `X-CWB-Org` and requires the `org:purge` scope (from `X-CWB-Scopes`). It is **idempotent**: zero matching data → `200`. herald (behind the gateway prefixes) calls `<gateway>/cairn/api/org`, `<gateway>/ledger/api/org`, `<gateway>/knowledge/api/org`.

---

## Task 1: herald store — `DeleteOrg` (deferred-FK cascade) + `ListOrgs`

**Files:**
- Modify: `internal/store/store.go` (the `Store` interface)
- Modify: `internal/store/sqlite.go`
- Test: `internal/store/store_test.go`

> NOTE: herald's schema declares NO `ON DELETE CASCADE` (the `user.org_id`, `user.responsible_human`, `scope_grant.user_id`, `scope_grant.granted_by`, `org_product.org_id` FKs are plain references). So `DELETE FROM org` alone FK-fails. `DeleteOrg` must delete children explicitly in one transaction with FK checks deferred to commit (handles the intra-org `responsible_human`/`granted_by` self-references).

- [ ] **Step 1: Extend the `Store` interface**

In `internal/store/store.go`, inside `type Store interface`, after the `// Orgs.` methods add:

```go
	// DeleteOrg removes an org and ALL its rows (users, their scope grants,
	// product overrides) in one transaction. Idempotent: an absent org is a
	// no-op (no error).
	DeleteOrg(ctx context.Context, id string) error
	// ListOrgs returns every org (id, name, status).
	ListOrgs(ctx context.Context) ([]Org, error)
```

- [ ] **Step 2: Write the failing test**

In `internal/store/store_test.go` add (match the file's store-open idiom — `store.Open(":memory:")` + `t.Cleanup`):

```go
func TestDeleteOrg_CascadesAndIsIdempotent(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "acme")
	h, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	a, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindAgent, DisplayName: "builder", ResponsibleHuman: h.ID})
	if _, err := s.GrantScope(ctx, a.ID, "repo:write", h.ID); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := s.SetProductEnabled(ctx, org.ID, "cairn", false); err != nil {
		t.Fatalf("set product: %v", err)
	}
	// A second org must be untouched.
	other, _ := s.CreateOrg(ctx, "other")

	if err := s.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("DeleteOrg: %v", err)
	}
	if _, err := s.GetOrg(ctx, org.ID); err != store.ErrNotFound {
		t.Fatalf("org should be gone, got %v", err)
	}
	if _, err := s.GetUser(ctx, a.ID); err != store.ErrNotFound {
		t.Fatalf("agent should be gone, got %v", err)
	}
	if sc, _ := s.ListScopes(ctx, a.ID); len(sc) != 0 {
		t.Fatalf("scope grants should be gone, got %v", sc)
	}
	if _, err := s.GetOrg(ctx, other.ID); err != nil {
		t.Fatalf("other org must be untouched, got %v", err)
	}
	// Idempotent: deleting again is a no-op.
	if err := s.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("DeleteOrg (again) should be no-op, got %v", err)
	}
}

func TestListOrgs(t *testing.T) {
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	a, _ := s.CreateOrg(ctx, "aa")
	b, _ := s.CreateOrg(ctx, "bb")
	orgs, err := s.ListOrgs(ctx)
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	got := map[string]string{}
	for _, o := range orgs {
		got[o.ID] = o.Name
	}
	if got[a.ID] != "aa" || got[b.ID] != "bb" {
		t.Fatalf("ListOrgs = %+v", orgs)
	}
}
```

Run: `go test ./internal/store/ -run 'TestDeleteOrg_CascadesAndIsIdempotent|TestListOrgs' -v` → FAIL (methods undefined).

- [ ] **Step 3: Implement `DeleteOrg` + `ListOrgs`**

In `internal/store/sqlite.go` add:

```go
func (s *SQLite) DeleteOrg(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("DeleteOrg: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Defer FK enforcement to COMMIT so intra-org self-references
	// (user.responsible_human, scope_grant.granted_by) don't fail mid-delete.
	// No-op when foreign_keys is off (e.g. :memory: tests).
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return fmt.Errorf("DeleteOrg: defer fk: %w", err)
	}
	// Clear grants both TO and BY this org's users (removes inbound FK refs).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM scope_grant WHERE user_id IN (SELECT id FROM user WHERE org_id=?)
		    OR granted_by IN (SELECT id FROM user WHERE org_id=?)`, id, id); err != nil {
		return fmt.Errorf("DeleteOrg: scope_grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_product WHERE org_id=?`, id); err != nil {
		return fmt.Errorf("DeleteOrg: org_product: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user WHERE org_id=?`, id); err != nil {
		return fmt.Errorf("DeleteOrg: user: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org WHERE id=?`, id); err != nil {
		return fmt.Errorf("DeleteOrg: org: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("DeleteOrg: commit: %w", err)
	}
	return nil
}

func (s *SQLite) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, status, created_at FROM org ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("ListOrgs: %w", err)
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		var status string
		if err := rows.Scan(&o.ID, &o.Name, &status, &o.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListOrgs scan: %w", err)
		}
		o.Status = Status(status)
		out = append(out, o)
	}
	return out, rows.Err()
}
```

> `BeginTx`, `fmt`, `database/sql` are available in `sqlite.go`. Confirm the `Org` struct's `Status` field type (`Status`) + `CreatedAt` matches `GetOrg`'s scan (it does — mirror `GetOrg`).

- [ ] **Step 4: Run — expect PASS**

`go test ./internal/store/ -run 'TestDeleteOrg|TestListOrgs' -v` → PASS; then `go test ./internal/store/` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/sqlite.go internal/store/store_test.go
git commit -m "store: DeleteOrg (deferred-FK cascade) + ListOrgs"
```

---

## Task 2: herald identity — passthroughs + `ScopeOrgPurge`

**Files:**
- Modify: `internal/identity/identity.go` (or `products.go` — wherever fits; a new `purge.go` is fine)
- Test: `internal/identity/identity_test.go` (or a new `purge_test.go`)

- [ ] **Step 1: Write the failing test**

Create `internal/identity/purge_test.go`:

```go
package identity_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestServiceDeleteOrgAndListOrgs(t *testing.T) {
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, "acme")
	orgs, err := svc.ListOrgs(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].ID != org.ID {
		t.Fatalf("ListOrgs = %+v, %v", orgs, err)
	}
	if err := svc.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("DeleteOrg: %v", err)
	}
	if _, err := svc.GetOrg(ctx, org.ID); err != store.ErrNotFound {
		t.Fatalf("org should be gone, got %v", err)
	}
}

func TestScopeOrgPurgeConstant(t *testing.T) {
	if identity.ScopeOrgPurge != "org:purge" {
		t.Fatalf("ScopeOrgPurge = %q", identity.ScopeOrgPurge)
	}
}
```

Run: `go test ./internal/identity/ -run 'TestServiceDeleteOrgAndListOrgs|TestScopeOrgPurgeConstant' -v` → FAIL.

- [ ] **Step 2: Implement**

Create `internal/identity/purge.go`:

```go
package identity

import (
	"context"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ScopeOrgPurge is the capability that authorizes a pillar's self-org purge
// (org wipe). It is minted ONLY into herald's ephemeral purge token and is
// never granted to a normal agent.
const ScopeOrgPurge = "org:purge"

// DeleteOrg removes an org and all its data from herald's store.
func (svc *Service) DeleteOrg(ctx context.Context, orgID string) error {
	return svc.store.DeleteOrg(ctx, orgID)
}

// ListOrgs returns all orgs (for the reaper's orphan discovery).
func (svc *Service) ListOrgs(ctx context.Context) ([]store.Org, error) {
	return svc.store.ListOrgs(ctx)
}
```

- [ ] **Step 3: Run — expect PASS**

`go test ./internal/identity/` → all PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/identity/purge.go internal/identity/purge_test.go
git commit -m "identity: DeleteOrg/ListOrgs passthrough + ScopeOrgPurge constant"
```

---

## Task 3: herald `internal/purge` — strict gateway-routed purge client

**Files:**
- Create: `internal/purge/purge.go`
- Test: `internal/purge/purge_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/purge/purge_test.go`:

```go
package purge_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/purge"
)

func TestPurgeOrg_AllSucceed(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer TOK" {
			t.Errorf("auth = %q", got)
		}
		seen = append(seen, r.URL.Path)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	c := purge.New(srv.URL, srv.Client())
	res, err := c.PurgeOrg(context.Background(), "org1", "TOK")
	if err != nil {
		t.Fatalf("PurgeOrg: %v", err)
	}
	for _, p := range []string{"cairn", "ledger", "commonplace"} {
		if res[p] != "ok" {
			t.Fatalf("result[%s] = %q, want ok (res=%+v)", p, res[p], res)
		}
	}
	// Hit each pillar's gateway prefix at /api/org.
	want := []string{"/cairn/api/org", "/ledger/api/org", "/knowledge/api/org"}
	for _, w := range want {
		found := false
		for _, s := range seen {
			if s == w {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a DELETE to %s; saw %v", w, seen)
		}
	}
}

func TestPurgeOrg_StrictAbortsOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ledger") {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	c := purge.New(srv.URL, srv.Client())
	_, err := c.PurgeOrg(context.Background(), "org1", "TOK")
	if err == nil || !strings.Contains(err.Error(), "ledger") {
		t.Fatalf("expected strict error naming ledger, got %v", err)
	}
}
```

Run: `go test ./internal/purge/ -v` → FAIL (package missing).

- [ ] **Step 2: Implement `internal/purge/purge.go`**

```go
// Package purge fans an org wipe out to the CWB data pillars through the
// interchange gateway. herald mints an org:purge token and this client calls
// each pillar's self-org DELETE /api/org behind its gateway prefix. Strict:
// the first non-2xx aborts (the caller then must NOT delete herald's own org).
package purge

import (
	"context"
	"fmt"
	"net/http"
)

// pillarPrefixes are the gateway path prefixes for the data pillars, in purge
// order. commonplace is fronted at /knowledge.
var pillarPrefixes = []struct{ name, prefix string }{
	{"cairn", "/cairn"},
	{"ledger", "/ledger"},
	{"commonplace", "/knowledge"},
}

// Client calls pillar purge routes through the gateway.
type Client struct {
	gatewayBase string
	http        *http.Client
}

// New builds a Client. gatewayBase is the interchange gateway root (no trailing
// slash needed), e.g. http://interchange-gateway.cwb.svc:8080.
func New(gatewayBase string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{gatewayBase: gatewayBase, http: hc}
}

// PurgeOrg DELETEs each pillar's /api/org with the given purge token. Strict:
// returns an error on the first pillar that responds non-2xx, naming it. On
// full success returns a per-pillar status map.
func (c *Client) PurgeOrg(ctx context.Context, orgID, purgeToken string) (map[string]string, error) {
	res := map[string]string{}
	for _, p := range pillarPrefixes {
		url := c.gatewayBase + p.prefix + "/api/org"
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if err != nil {
			return res, fmt.Errorf("purge %s: build request: %w", p.name, err)
		}
		req.Header.Set("Authorization", "Bearer "+purgeToken)
		resp, err := c.http.Do(req)
		if err != nil {
			return res, fmt.Errorf("purge %s: %w", p.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return res, fmt.Errorf("purge %s: status %d", p.name, resp.StatusCode)
		}
		res[p.name] = "ok"
	}
	return res, nil
}
```

- [ ] **Step 3: Run — expect PASS**

`go test ./internal/purge/ -v` → PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/purge/purge.go internal/purge/purge_test.go
git commit -m "purge: strict gateway-routed cross-pillar org purge client"
```

---

## Task 4: herald adminapi — `GET /api/orgs` + `DELETE /api/orgs/{id}` + wiring

**Files:**
- Modify: `internal/adminapi/adminapi.go`
- Modify: `cmd/herald/main.go`
- Test: `internal/adminapi/adminapi_test.go`

> The `API` struct already holds `a.id` (identity, used as `a.id.CreateOrg`) and `a.tokens` (the oidc provider, used as `a.tokens.SignToken(claims)`). We add a `purger` dependency (a `*purge.Client`) and the two routes. The purge token is built inline and signed with `a.tokens.SignToken` (which stamps `iss`/`iat`/`exp`).

- [ ] **Step 1: Write the failing tests**

In `internal/adminapi/adminapi_test.go` add (reuse the file's harness; for the purge dependency, inject a STUB so the handler tests don't need a live gateway). Define a tiny stub matching the purger interface the handler calls:

```go
// stubPurger records calls and returns a configurable error.
type stubPurger struct {
	called  bool
	lastOrg string
	err     error
}

func (s *stubPurger) PurgeOrg(ctx context.Context, orgID, token string) (map[string]string, error) {
	s.called = true
	s.lastOrg = orgID
	if s.err != nil {
		return nil, s.err
	}
	return map[string]string{"cairn": "ok", "ledger": "ok", "commonplace": "ok"}, nil
}

func TestDeleteOrg_ConfirmByNameAndCascade(t *testing.T) {
	// Build the API with the stub purger. Match the suite's existing
	// constructor; New now takes the purger (see Step 4). Provision an org via
	// POST /api/orgs (or the suite's helper) to get its id+name.
	sp := &stubPurger{}
	api, admin := newTestAPIWithPurger(t, sp) // see note below
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	org := createOrg(t, srv, admin, "acme") // {id}; name = "acme"

	// Wrong name → 409, purge NOT called, org still listed.
	code, _ := doJSON(t, srv, admin, "DELETE", "/api/orgs/"+org, map[string]any{"name": "WRONG"})
	if code != 409 || sp.called {
		t.Fatalf("wrong name: code=%d purged=%v, want 409 + no purge", code, sp.called)
	}

	// Missing org → 404.
	code, _ = doJSON(t, srv, admin, "DELETE", "/api/orgs/no-such", map[string]any{"name": "x"})
	if code != 404 {
		t.Fatalf("missing org = %d, want 404", code)
	}

	// Correct name → purge called, then 200; org no longer listed.
	code, body := doJSON(t, srv, admin, "DELETE", "/api/orgs/"+org, map[string]any{"name": "acme"})
	if code != 200 || !sp.called || sp.lastOrg != org {
		t.Fatalf("delete = %d purged=%v org=%s body=%+v", code, sp.called, sp.lastOrg, body)
	}
	code, list := doJSON(t, srv, admin, "GET", "/api/orgs", nil)
	if code != 200 {
		t.Fatalf("list = %d", code)
	}
	// list is an array; assert org id absent (adapt to doJSON's array decode).
	if listContainsOrg(list, org) {
		t.Fatalf("deleted org still listed")
	}
}

func TestDeleteOrg_StrictPurgeFailureLeavesOrg(t *testing.T) {
	sp := &stubPurger{err: errors.New("purge ledger: status 500")}
	api, admin := newTestAPIWithPurger(t, sp)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	org := createOrg(t, srv, admin, "acme")

	code, _ := doJSON(t, srv, admin, "DELETE", "/api/orgs/"+org, map[string]any{"name": "acme"})
	if code != 502 {
		t.Fatalf("purge failure = %d, want 502", code)
	}
	// Org must still exist (herald identity not deleted on strict abort).
	code, _ = doJSON(t, srv, admin, "GET", "/api/orgs/"+org+"/products", nil)
	if code == 404 {
		t.Fatalf("org should still exist after strict purge abort")
	}
}
```

> Adapt `newTestAPIWithPurger`/`createOrg`/`doJSON`/`listContainsOrg` to the suite's real helpers. If the existing constructor helper is `newStack`, extend it (or add a variant) to pass a purger. The `doJSON` for a `GET /api/orgs` returns a JSON array — decode into `[]any` / `[]map[string]any` as the suite does for list responses; `listContainsOrg` checks for the id.

Run: `go test ./internal/adminapi/ -run TestDeleteOrg -v` → FAIL.

- [ ] **Step 2: Define the purger interface + add it to `API`**

In `internal/adminapi/adminapi.go`, near the other small interfaces (e.g. the `Identity`/`TokenIssuer` interfaces), add:

```go
// OrgPurger fans an org wipe out to the data pillars (herald's internal/purge).
type OrgPurger interface {
	PurgeOrg(ctx context.Context, orgID, purgeToken string) (map[string]string, error)
}
```

Add a field to the `API` struct:

```go
	purger OrgPurger
```

- [ ] **Step 3: Register routes**

In `Handler()`, after the `POST /api/orgs` registration add:

```go
	mux.HandleFunc("GET /api/orgs", a.adminOnly(a.handleListOrgs))
	mux.HandleFunc("DELETE /api/orgs/{id}", a.adminOnly(a.handleDeleteOrg))
```

- [ ] **Step 4: Implement the handlers**

Add to `internal/adminapi/adminapi.go` (import `"github.com/CarriedWorldUniverse/herald/internal/identity"` and `"github.com/CarriedWorldUniverse/herald/internal/store"` if not already; `errors` is imported):

```go
func (a *API) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := a.id.ListOrgs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list orgs failed")
		return
	}
	out := make([]map[string]any, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, map[string]any{"id": o.ID, "name": o.Name, "status": string(o.Status)})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	org, err := a.id.GetOrg(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "org not found")
		return
	}
	if body.Name == "" || body.Name != org.Name {
		writeErr(w, http.StatusConflict, "org name confirmation does not match")
		return
	}
	// Mint the ephemeral purge token: all products so the gateway entitlement
	// gate passes for every pillar; org:purge scope; synthetic subject.
	token, err := a.tokens.SignToken(map[string]any{
		"sub":      "system:purge",
		"kind":     string(store.KindAgent),
		"org":      id,
		"scope":    identity.ScopeOrgPurge,
		"products": identity.CanonicalProducts,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "mint purge token failed")
		return
	}
	// Strict: any pillar failure aborts; herald's own org is NOT deleted.
	pillars, err := a.purger.PurgeOrg(r.Context(), id, token)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "pillar purge failed: "+err.Error())
		return
	}
	if err := a.id.DeleteOrg(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "herald org delete failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id, "pillars": pillars})
}
```

> `a.id` must expose `GetOrg`, `ListOrgs`, `DeleteOrg` (the `Identity` interface in this file — widen it to include `ListOrgs(ctx) ([]store.Org, error)` and `DeleteOrg(ctx, string) error`; `GetOrg` was added in the entitlement work). `a.tokens.SignToken` already exists. `identity.CanonicalProducts` came from the entitlement work.

- [ ] **Step 5: Wire the purger in `cmd/herald/main.go`**

Update the `adminapi.New(...)` call to pass a `*purge.Client`. Derive the gateway base from `HERALD_GATEWAY_URL` (explicit), falling back to the issuer with the `/herald/` suffix trimmed:

```go
	gatewayBase := os.Getenv("HERALD_GATEWAY_URL")
	if gatewayBase == "" {
		gatewayBase = strings.TrimSuffix(strings.TrimRight(issuer, "/")+"/", "/herald/")
	}
	purger := purge.New(gatewayBase, &http.Client{Timeout: 30 * time.Second})
	api := adminapi.New(idsvc, provider, adminToken, purger)
```

Update `adminapi.New`'s signature to accept the purger as a 4th arg and store it in `a.purger` (and update any other call sites + the test constructor helper). Add imports `"net/http"`, `"strings"`, `"time"`, and `"github.com/CarriedWorldUniverse/herald/internal/purge"` to `cmd/herald/main.go`.

- [ ] **Step 6: Run — expect PASS**

`go test ./internal/adminapi/ -v` → PASS; then from herald root `go build ./... && go test ./... && go vet ./...` → all green.

- [ ] **Step 7: Commit**

```bash
git add internal/adminapi/adminapi.go cmd/herald/main.go internal/adminapi/adminapi_test.go
git commit -m "adminapi: GET /api/orgs + DELETE /api/orgs/{id} (confirm-by-name, strict cross-pillar purge)"
```

---

## Task 5: cairn — self-org purge `DELETE /api/org`

**Repo:** `/Users/jacinta/Source/cairn`, branch `feat/nex-402-org-purge` (create it).

**Files:**
- Modify: `internal/httpd/server.go`
- Test: `internal/httpd/*_test.go` (match the suite)
- (uses existing `repo.Service.ListRepos(ctx, orgID)` + `DeleteRepo(ctx, id)`)

- [ ] **Step 0: Branch**

```bash
cd /Users/jacinta/Source/cairn && git checkout main && git pull --ff-only && git checkout -b feat/nex-402-org-purge
```

- [ ] **Step 1: Write the failing test**

In the httpd test suite, add a test that hits `DELETE /api/org` with `X-CWB-*` headers carrying `org:purge` and asserts the org's repos are gone (and 403 without the scope). Mirror the existing handler tests' way of constructing a `Server` + setting `X-CWB-Subject/Org/Scopes` headers. Skeleton:

```go
func TestHandleOrgPurge(t *testing.T) {
	srv := newTestServer(t) // the suite's helper; gives a *Server + repo.Service
	// Create two repos in org "o1" (use the suite's create helper or core.CreateRepo).
	mustCreateRepo(t, srv, "o1", "r1")
	mustCreateRepo(t, srv, "o1", "r2")

	// No org:purge scope → 403.
	req := httptest.NewRequest("DELETE", "/api/org", nil)
	req.Header.Set("X-CWB-Subject", "sys")
	req.Header.Set("X-CWB-Org", "o1")
	req.Header.Set("X-CWB-Scopes", "repo:read")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no scope = %d, want 403", rr.Code)
	}

	// With org:purge → 200 and repos gone.
	req = httptest.NewRequest("DELETE", "/api/org", nil)
	req.Header.Set("X-CWB-Subject", "sys")
	req.Header.Set("X-CWB-Org", "o1")
	req.Header.Set("X-CWB-Scopes", "org:purge")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge = %d, want 200", rr.Code)
	}
	if repos, _ := srv.cfg.Core.ListRepos(context.Background(), "o1"); len(repos) != 0 {
		t.Fatalf("repos should be gone, got %d", len(repos))
	}

	// Idempotent: purging again (no repos) is still 200.
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest2("DELETE", "/api/org", "o1", "org:purge")) // adapt to suite helper
	if rr.Code != http.StatusOK {
		t.Fatalf("idempotent purge = %d, want 200", rr.Code)
	}
}
```

> Adapt to the suite's actual server/test helpers (constructing `*Server`, creating repos, setting headers). The behavioral asserts (403 without scope; 200 + repos gone with scope; idempotent 200) are the contract.

Run the test → FAIL (route missing).

- [ ] **Step 2: Register the route + handler**

In `internal/httpd/server.go` `Handler()`, add (before the catch-all `mux.HandleFunc("/", s.handleGit)`):

```go
	mux.HandleFunc("DELETE /api/org", s.handleOrgPurge)
```

Add the handler (mirror `handleCreateRepo`'s identity/scope gating):

```go
// handleOrgPurge deletes ALL repos for the caller's org (X-CWB-Org), gated by
// the org:purge scope. Used by herald's cross-org wipe (NEX-402). Operates only
// on the auth org — no org in the path. Idempotent: zero repos → 200.
func (s *Server) handleOrgPurge(w http.ResponseWriter, r *http.Request) {
	id, ok := identityFromHeaders(r)
	if !ok {
		httpErr(w, http.StatusUnauthorized, "missing identity")
		return
	}
	if !id.HasScope("org:purge") {
		httpErr(w, http.StatusForbidden, "missing scope org:purge")
		return
	}
	repos, err := s.cfg.Core.ListRepos(r.Context(), id.Org)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, "list repos failed")
		return
	}
	for _, rp := range repos {
		if err := s.cfg.Core.DeleteRepo(r.Context(), rp.ID); err != nil {
			httpErr(w, http.StatusInternalServerError, "delete repo failed: "+err.Error())
			return
		}
	}
	writeJSONOK(w, map[string]any{"purged": id.Org, "repos": len(repos)})
}
```

> Use the file's existing JSON-write helper (e.g. the one `handleCreateRepo` uses) instead of `writeJSONOK` if named differently. Confirm `repo.Repo` exposes `.ID` (it does) and `ListRepos`/`DeleteRepo` signatures (confirmed: `ListRepos(ctx, orgID) ([]Repo, error)`, `DeleteRepo(ctx, id) error`).

- [ ] **Step 3: Run — expect PASS**, then `go test ./... && go vet ./...`.

- [ ] **Step 4: Commit**

```bash
git add internal/httpd/server.go internal/httpd/*_test.go
git commit -m "cairn: DELETE /api/org self-org purge (org:purge) for cross-org wipe"
```

---

## Task 6: commonplace — self-org purge `DELETE /api/org`

**Repo:** `/Users/jacinta/Source/commonplace`, branch `feat/nex-402-org-purge`.

**Files:**
- Modify: `handlers.go`, `crud.go` (or `store.go`)
- Test: the package test file

- [ ] **Step 0: Branch** (`git checkout main && git pull --ff-only && git checkout -b feat/nex-402-org-purge`)

- [ ] **Step 1: Write the failing test**

Add a test: store two entries in org "o1" (builder), then `DELETE /api/org` with `X-CWB-Org=o1`, `X-CWB-Scopes=org:purge` → 200, and a search/list for o1 returns nothing; without the scope → 403. Mirror the existing handler tests' header-injection + `Handler()` invocation. Behavioral contract:
- no `org:purge` scope → 403
- with scope → 200, entries for o1 gone (a subsequent list/search by an o1 identity returns 0)
- idempotent: second purge → 200

Run → FAIL.

- [ ] **Step 2: Add `DeleteByOrg` (mirror `Delete`)**

In `crud.go` add:

```go
// DeleteByOrg removes ALL entries for an org (and their fts/vec rows). Used by
// the cross-org wipe (NEX-402). Idempotent: zero entries → nil.
func (s *Service) DeleteByOrg(ctx context.Context, org string) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("commonplace: DeleteByOrg: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM entry_fts WHERE entry_id IN (SELECT id FROM entry WHERE org=?)`, org); err != nil {
		return 0, fmt.Errorf("commonplace: DeleteByOrg: fts: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM entry_vec WHERE entry_id IN (SELECT id FROM entry WHERE org=?)`, org); err != nil {
		return 0, fmt.Errorf("commonplace: DeleteByOrg: vec: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM entry WHERE org=?`, org)
	if err != nil {
		return 0, fmt.Errorf("commonplace: DeleteByOrg: entry: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commonplace: DeleteByOrg: commit: %w", err)
	}
	return int(n), nil
}
```

- [ ] **Step 3: Register the route + handler**

In `handlers.go`, in the `api` mux add:

```go
	api.HandleFunc("DELETE /api/org", s.handleOrgPurge)
```

Add the handler (mirror `handleDelete`'s identity-from-context + scope gating):

```go
func (s *Service) handleOrgPurge(w http.ResponseWriter, r *http.Request) {
	id := identityFromContext(r.Context())
	if !id.hasScope("org:purge") {
		http.Error(w, `{"error":"missing scope org:purge"}`, http.StatusForbidden)
		return
	}
	n, err := s.DeleteByOrg(r.Context(), id.Org)
	if err != nil {
		http.Error(w, `{"error":"purge failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"purged": id.Org, "entries": n})
}
```

> Use the file's existing JSON writer (match `handleStore`/`handleList`). The `withIdentity` middleware already requires `X-CWB-Subject` + `X-CWB-Org`, so identity is present.

- [ ] **Step 4: Run — expect PASS**, then `go test ./... && go vet ./...`.

- [ ] **Step 5: Commit**

```bash
git add handlers.go crud.go *_test.go
git commit -m "commonplace: DELETE /api/org self-org purge (org:purge) for cross-org wipe"
```

---

## Task 7: ledger — self-org purge `DELETE /api/org`

**Repo:** `/Users/jacinta/Source/ledger`, branch `feat/nex-402-org-purge`.

**Files:**
- Modify: `organisations.go` (idempotent purge), `rest.go` (route), `cmd/ledger/middleware.go` (scope mapping)
- Test: the package test files

- [ ] **Step 0: Branch.**

- [ ] **Step 1: Write the failing test**

Two tests:
(a) store-level: `PurgeOrganisation` deletes an org + cascades projects/issues, and is a no-op (nil) for an absent slug.
(b) middleware: `scopeForMethodPath(http.MethodDelete, "/api/org")` returns `"org:purge"`.
Run → FAIL.

- [ ] **Step 2: Add idempotent `PurgeOrganisation`**

In `organisations.go` add (the existing `DeleteOrganisation` errors on 0 rows; the purge must be idempotent):

```go
// PurgeOrganisation deletes an org and cascades its projects/issues. Unlike
// DeleteOrganisation it is idempotent: an absent slug is a no-op (nil). Used by
// the cross-org wipe (NEX-402).
func (s *Service) PurgeOrganisation(ctx context.Context, slug string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM organisations WHERE slug = ?`, slug); err != nil {
		return fmt.Errorf("PurgeOrganisation: %w", err)
	}
	return nil
}
```

> Confirm the schema cascades `projects.organisation → organisations.slug ON DELETE CASCADE` and `issues.project → projects.key ON DELETE CASCADE`, and that ledger opens its DB with `PRAGMA foreign_keys=ON` (it must, for the cascade). If FKs are not enabled or CASCADE is absent, also delete dependent rows explicitly in a tx (projects + issues for the org) — check `schema.sql` and add the explicit deletes if needed. Add a test asserting an org's project+issue are gone after PurgeOrganisation.

- [ ] **Step 3: Map the scope + register the route**

In `cmd/ledger/middleware.go` `scopeForMethodPath`, add a case (before the generic fallbacks):

```go
	case method == http.MethodDelete && path == "/api/org":
		return "org:purge"
```

In `rest.go` `Handler()`, register:

```go
	mux.HandleFunc("DELETE /api/org", s.handleOrgPurge)
```

Add the handler (reads `AuthFromContext`):

```go
func (s *Service) handleOrgPurge(w http.ResponseWriter, r *http.Request) {
	claims := AuthFromContext(r.Context())
	if claims == nil || claims.Org == "" {
		http.Error(w, `{"error":"no org context"}`, http.StatusBadRequest)
		return
	}
	if err := s.PurgeOrganisation(r.Context(), claims.Org); err != nil {
		http.Error(w, `{"error":"purge failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"purged": claims.Org})
}
```

> The gateway-mode middleware enforces the `org:purge` scope via `scopeForMethodPath` before the handler runs (mirrors how other ledger routes are scope-gated), so the handler itself only needs the org from claims. Confirm the scope-enforcement middleware actually rejects a token lacking the mapped scope (it should — that's how `issue:admin` routes are guarded); if enforcement is advisory, add an explicit `claims`-scope check. `json` is imported in rest.go.

- [ ] **Step 4: Run — expect PASS**, then `go test ./... && go vet ./...`.

- [ ] **Step 5: Commit**

```bash
git add organisations.go rest.go cmd/ledger/middleware.go *_test.go
git commit -m "ledger: DELETE /api/org self-org purge (org:purge) for cross-org wipe"
```

---

## Task 8: cwb-conformance — rewire teardown/reap + reap layer

**Repo:** `/Users/jacinta/Source/cwb-conformance`, branch `feat/nex-402-reap`.

**Files:**
- Modify: `internal/fixtures/teardown.go`
- Modify: `cmd/cwb-conform/main.go` (`reapOrphans` + `allLayers`)
- Create: `conformance/reap/reap_test.go` + `conformance/reap/doc.go`

- [ ] **Step 0: Branch.**

- [ ] **Step 1: Rewire `Teardown` to herald DELETE**

In `internal/fixtures/teardown.go`, replace the per-human `block` loop with a single org DELETE (best-effort, never fails the run):

```go
func Teardown(t *testing.T, tgt *target.Target, org *TestOrg) {
	ctx := context.Background()
	base := tgt.HeraldAdminBase()
	url := fmt.Sprintf("%s/api/orgs/%s", base, org.OrgID)
	resp, raw, err := wire.DeleteJSON(ctx, url, tgt.AdminToken, map[string]any{"name": org.OrgName})
	if err != nil {
		t.Logf("teardown: DELETE org %s: transport error, leaving in place: %v", org.OrgID, err)
		return
	}
	if resp.StatusCode/100 == 2 {
		t.Logf("teardown: wiped org %s across all pillars", org.OrgID)
		return
	}
	t.Logf("teardown: DELETE org %s returned %d (left as orphan): %s", org.OrgID, resp.StatusCode, raw)
}
```

> `TestOrg` must carry the org NAME (for confirm-by-name). It currently has `OrgID`; add an `OrgName string` field in `internal/fixtures/org.go` and set it in `ProvisionOrg` (`OrgName: orgName`). Use that here (`org.OrgName`). If `wire` has no `DeleteJSON`, add one mirroring `PostJSON` but with `http.MethodDelete` (body = the JSON confirm payload). Keep teardown best-effort — never `t.Fatal`.

- [ ] **Step 2: Make `-reap` real**

In `cmd/cwb-conform/main.go`, replace the `reapOrphans` stub with a real sweep: `GET <HeraldAdminBase>/api/orgs`, filter names with prefix `cwb-test-`, `DELETE` each with its name, log a count. (Use the same wire helpers + admin token the harness already loads from env.) Keep it best-effort + logged.

- [ ] **Step 3: Add the reap conformance layer**

Add `"reap"` to `allLayers` in `cmd/cwb-conform/main.go` (after `"journey"`). Create `conformance/reap/reap_test.go`:

```go
package reap

import (
	"context"
	"net/http"
	"testing"

	"github.com/CarriedWorldUniverse/cwb-conformance/internal/fixtures"
	"github.com/CarriedWorldUniverse/cwb-conformance/internal/harness"
	"github.com/CarriedWorldUniverse/cwb-conformance/internal/target"
	"github.com/CarriedWorldUniverse/cwb-conformance/internal/wire"
)

// TestReapLayer proves the cross-pillar wipe: provision an org with data in
// cairn (a repo), ledger (an issue), and commonplace (an entry), DELETE the org
// via herald, then assert each pillar no longer has it and herald no longer
// lists it. Does NOT use the shared Teardown (it deletes the org itself).
func TestReapLayer(t *testing.T) {
	tgt := harness.RequireTarget(t)
	org := fixtures.ProvisionOrg(t, tgt)
	// Intentionally NOT registering Teardown — this test deletes the org.

	// 1. Write data in each pillar as builder (knowledge entry; a repo; an issue).
	//    Reuse the helpers the commonplace/cairn/ledger layers use, or inline a
	//    knowledge store (simplest reliable signal) + a cairn repo create.
	builder := org.Agents["builder"]
	storeKnowledge(t, tgt, builder.Token, "reap-canary "+tgt.RunID) // -> entry id
	createRepo(t, tgt, builder.Token, org.OrgID, "reap-repo")

	// 2. Wipe via herald (admin-direct), confirm-by-name.
	delURL := tgt.HeraldAdminBase() + "/api/orgs/" + org.OrgID
	resp, raw, err := wire.DeleteJSON(context.Background(), delURL, tgt.AdminToken, map[string]any{"name": org.OrgName})
	if err != nil {
		t.Fatalf("DELETE org: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE org = %d: %s", resp.StatusCode, raw)
	}

	// 3. herald no longer lists the org.
	if orgListed(t, tgt, org.OrgID) {
		t.Fatalf("org still listed by herald after wipe")
	}
	// 4. commonplace: a fresh token can't be minted (org gone) — assert via
	//    admin GET /api/orgs absence (step 3) which is the herald source of truth.
	//    Optionally: re-provision-independent probes per pillar if helpers exist.
	t.Logf("reap: org %s wiped across pillars + delisted from herald", org.OrgID)
}
```

> Fill `storeKnowledge`/`createRepo`/`orgListed` using the existing wire helpers (the commonplace layer's store call; the cairn layer's repo-create; a `GET /api/orgs` + scan). The load-bearing assertions are: DELETE → 200, and herald `GET /api/orgs` no longer contains the org. If you can cheaply probe a pillar post-wipe (e.g. the repo 404s via the gateway), add it; the herald delisting is the minimum proof. Add a one-line `doc.go` matching the other layers.

- [ ] **Step 4: Verify locally** (`go build ./... && go vet ./... && go test ./...` — layers SKIP without a live target; compilation is the local gate).

- [ ] **Step 5: Commit (+ PR)**

```bash
git add internal/fixtures/ cmd/cwb-conform/main.go conformance/reap/ internal/wire/
git commit -m "conformance: real org wipe in teardown + -reap + reap layer (NEX-402)"
```

---

## Task 9: deploy + verify (controller / dMon ops)

- [ ] **Step 1: Merge PRs in dependency order.** herald first (it's the orchestrator + the pillars don't depend on it at build time, but deploy herald last so the endpoint appears only once pillars can purge). Open + CI-green + squash-merge each: herald `feat/nex-402-org-wipe`, cairn/commonplace/ledger `feat/nex-402-org-purge`, cwb-conformance `feat/nex-402-reap`. Verify each `mergedAt`.

- [ ] **Step 2: Redeploy the four pillars on dMon**, herald LAST (so its DELETE endpoint only goes live once every pillar can service a purge):

```bash
ssh jacinta@100.91.185.71 'set -e
  for r in cairn commonplace ledger interchange herald; do cd ~/src/$r && git checkout main && git pull --ff-only; done
  # build+import each changed image (cairn, commonplace, ledger, herald), e.g.:
  cd ~/src/cairn && podman build -q -f cmd/cairn/Containerfile -t localhost/cairn:dev . && podman save localhost/cairn:dev | sudo k3s ctr images import -
  # ... repeat for commonplace, ledger, herald (confirm each Containerfile path) ...
  # Set herald gateway URL to the in-cluster gateway service so purge calls do not hairpin via tailnet:
  sudo kubectl set env deploy/herald -n cwb HERALD_GATEWAY_URL=http://interchange-gateway.cwb.svc:8080
  sudo kubectl rollout restart deploy/cairn deploy/commonplace deploy/ledger -n cwb
  sudo kubectl rollout status deploy/cairn deploy/commonplace deploy/ledger -n cwb --timeout=120s
  sudo kubectl rollout restart deploy/herald -n cwb
  sudo kubectl rollout status deploy/herald -n cwb --timeout=120s'
```

> Confirm the gateway service name + port (`kubectl get svc -n cwb interchange-gateway`) and each Containerfile path before running. `HERALD_GATEWAY_URL` must point at the in-cluster gateway so herald → gateway → pillar stays in-cluster.

- [ ] **Step 3: Run the full conformance suite** (includes the new `reap` layer + a regression pass over all others):

```bash
ssh jacinta@100.91.185.71 'set -e
  cd ~/src/cwb-conformance && git pull -q
  CIP=$(sudo kubectl get svc herald -n cwb -o jsonpath="{.spec.clusterIP}")
  ADMIN=$(sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.admin_token}" | base64 -d)
  CWB_ADMIN_TOKEN="$ADMIN" CWB_HERALD_ADMIN_URL="http://$CIP:8099" CWB_RUN_ID="nex402-$(date +%s)" \
    go run ./cmd/cwb-conform -target dmon -layers all'
```
Expected: rc=0; the `reap` layer logs the wipe; the other layers' `Teardown` now actually deletes their orgs (no new orphans).

- [ ] **Step 4: Sweep the accumulated orphans + confirm.** Run `-reap` to wipe the backlog of `cwb-test-*` orgs, then confirm via `GET /api/orgs`:

```bash
ssh jacinta@100.91.185.71 'cd ~/src/cwb-conformance
  CIP=$(sudo kubectl get svc herald -n cwb -o jsonpath="{.spec.clusterIP}")
  ADMIN=$(sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.admin_token}" | base64 -d)
  CWB_ADMIN_TOKEN="$ADMIN" CWB_HERALD_ADMIN_URL="http://$CIP:8099" go run ./cmd/cwb-conform -target dmon -reap
  curl -s -H "Authorization: Bearer $ADMIN" http://$CIP:8099/api/orgs | grep -c cwb-test || echo "0 cwb-test orgs remain"'
```

- [ ] **Step 5: Close NEX-402** via the jira MCP with a summary (endpoint, strict semantics, the four pillar purge routes, the reaper, conformance reap-layer green, orphan backlog swept).

---

## Notes for the implementer / controller

- **No DB migrations.** `DeleteOrg`/purges are deletes against existing schemas. The herald cascade uses deferred FKs; pillar purges rely on each pillar's existing FK cascade (cairn `push_event`/`pull_request`, ledger `projects`/`issues`, commonplace `entry_vec`) plus explicit fts deletes — verify FKs are ON per service where cascade is assumed (ledger especially).
- **Uniform org-bound route:** every pillar purge is `DELETE /api/org`, operates on `X-CWB-Org`, requires `org:purge`. No org/slug in any path — this is the tenancy rule the operator set.
- **Strict ordering:** herald deletes its own identity ONLY after all pillar purges return 2xx. A failure → 502, herald org intact, idempotent retry.
- **Helper names** (`newTestAPIWithPurger`, `doJSON`, `newTestServer`, `storeKnowledge`, etc.) are illustrative — match each suite's real helpers; add minimal ones only if absent.
- **`a.id` interface widening (Task 4):** add `ListOrgs(ctx) ([]store.Org, error)` and `DeleteOrg(ctx, string) error` to the adminapi `Identity` interface; `GetOrg` + `CanonicalProducts` already exist from the entitlement work.
- **YAGNI:** no 2PC/rollback, no soft-delete, no per-product wipe, no operator UI — all named future work in the spec.
- **Ordering:** Tasks 1→4 (herald) are sequential; 5/6/7 (pillars) are independent of each other and depend only on the `org:purge`/`X-CWB` contract; 8 (conformance) needs the herald DELETE endpoint to exist; 9 deploys all.
```
