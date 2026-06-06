# Per-Org Product Entitlement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an org enable/disable each CWB product (`cairn`/`ledger`/`commonplace`); herald stamps the org's enabled products into every minted token and the interchange gateway returns `403` for a request to a disabled product's route prefix.

**Architecture:** A deny-list table `org_product` in herald (a product is enabled unless an `enabled=0` row exists — migration-free for existing orgs). herald's identity layer exposes the canonical product set + enable/disable + `EnabledProducts`; both token grants add a `products` claim; `heraldauth` parses it; the gateway maps route-prefix→product and enforces against the verified claim. Pillars are unchanged — enforcement is one choke point at the gateway.

**Tech Stack:** Go, SQLite (modernc), go-jose (herald token signing), `net/http` reverse proxy (interchange gateway).

**Spec:** `docs/2026-06-01-org-product-entitlement-spec.md`

**Repos & branches:**
- Tasks 1–5: **herald** repo (`/Users/jacinta/Source/herald`), branch `feat/org-product-entitlement` (already checked out).
- Task 6: **interchange** repo (`/Users/jacinta/Source/interchange`), new branch `feat/product-entitlement`.
- Task 7: deploy/ops (controller; SSH to dMon). "Verification" replaces unit tests there.

---

## File structure

**herald** (`/Users/jacinta/Source/herald`):
- Modify `internal/store/schema.sql` — add the `org_product` table.
- Modify `internal/store/store.go` — add three methods to the `Store` interface.
- Modify `internal/store/sqlite.go` — implement them.
- Modify `internal/store/store_test.go` — store unit tests.
- Create `internal/identity/products.go` — canonical set, `ErrUnknownProduct`, enable/disable, `Products`/`EnabledProducts`, `CreateOrgWithProducts`.
- Create `internal/identity/products_test.go` — identity unit tests.
- Modify `internal/oidc/agent_grant.go` + `internal/oidc/human_grant.go` — add `EnabledProducts` to the resolver interfaces and the `products` claim.
- Modify `internal/oidc/agent_grant_test.go` + `internal/oidc/human_grant_test.go` — assert the claim.
- Modify `internal/adminapi/adminapi.go` — three product routes + `products` on create-org.
- Modify `internal/adminapi/adminapi_test.go` — adminapi unit tests.
- Modify `heraldauth/heraldauth.go` — `Products` field + claim parse.
- Modify `heraldauth/heraldauth_test.go` — parse test.

**interchange** (`/Users/jacinta/Source/interchange`):
- Modify `internal/gateway/gateway.go` — `Products` on `Identity`, `RouteProducts` config, `route.product`, `403` enforcement, inject+strip `X-CWB-Products`.
- Modify `internal/gateway/gateway_test.go` — enforcement tests.
- Modify `cmd/interchange-gateway/main.go` — map `Products` in the adapter + wire `RouteProducts`.

---

## Task 1: store — `org_product` table + accessors

**Files:**
- Modify: `internal/store/schema.sql`
- Modify: `internal/store/store.go` (the `Store` interface)
- Modify: `internal/store/sqlite.go`
- Test: `internal/store/store_test.go`

- [ ] **Step 1: Add the schema**

In `internal/store/schema.sql`, append after the existing tables:

```sql
-- Per-org product entitlement (deny-list): a product is ENABLED unless a row
-- with enabled=0 exists. Absent row = enabled. herald is core (never listed).
CREATE TABLE IF NOT EXISTS org_product (
  org_id     TEXT NOT NULL REFERENCES org(id),
  product    TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org_id, product)
);
```

- [ ] **Step 2: Extend the `Store` interface**

In `internal/store/store.go`, inside `type Store interface`, after the `// Scopes.` block add:

```go
	// Product entitlement (deny-list: an absent row OR enabled=1 means
	// the product is enabled for the org).
	SetProductEnabled(ctx context.Context, orgID, product string, enabled bool) error
	IsProductEnabled(ctx context.Context, orgID, product string) (bool, error)
	ListProductOverrides(ctx context.Context, orgID string) (map[string]bool, error)
```

- [ ] **Step 3: Write the failing store tests**

In `internal/store/store_test.go` (package `store_test`), add:

```go
func TestProductEntitlement_DenyList(t *testing.T) {
	s := openTestStore(t) // use the same helper the other tests use to open an in-memory store
	ctx := context.Background()
	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// Default: no rows → every product enabled.
	if ok, err := s.IsProductEnabled(ctx, org.ID, "cairn"); err != nil || !ok {
		t.Fatalf("default cairn enabled = %v,%v want true,nil", ok, err)
	}

	// Disable → enabled=false; other products unaffected.
	if err := s.SetProductEnabled(ctx, org.ID, "cairn", false); err != nil {
		t.Fatalf("SetProductEnabled false: %v", err)
	}
	if ok, _ := s.IsProductEnabled(ctx, org.ID, "cairn"); ok {
		t.Fatalf("cairn should be disabled")
	}
	if ok, _ := s.IsProductEnabled(ctx, org.ID, "ledger"); !ok {
		t.Fatalf("ledger should still be enabled (deny-list)")
	}

	// Re-enable (idempotent upsert).
	if err := s.SetProductEnabled(ctx, org.ID, "cairn", true); err != nil {
		t.Fatalf("SetProductEnabled true: %v", err)
	}
	if ok, _ := s.IsProductEnabled(ctx, org.ID, "cairn"); !ok {
		t.Fatalf("cairn should be enabled after re-enable")
	}

	// Overrides reflect only rows that exist.
	if err := s.SetProductEnabled(ctx, org.ID, "ledger", false); err != nil {
		t.Fatalf("disable ledger: %v", err)
	}
	ov, err := s.ListProductOverrides(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListProductOverrides: %v", err)
	}
	if ov["cairn"] != true || ov["ledger"] != false {
		t.Fatalf("overrides = %+v, want cairn:true ledger:false", ov)
	}
	if _, present := ov["commonplace"]; present {
		t.Fatalf("commonplace has no row; must not appear in overrides")
	}
}
```

> Match the existing test's store-open helper. If the file opens stores inline as `store.Open(":memory:")`, replace `openTestStore(t)` with that and a `t.Cleanup(func(){ s.Close() })`.

- [ ] **Step 4: Run the test — expect FAIL**

Run: `go test ./internal/store/ -run TestProductEntitlement_DenyList -v`
Expected: compile error / FAIL (methods not implemented).

- [ ] **Step 5: Implement the accessors**

In `internal/store/sqlite.go`, add (near the other `*SQLite` methods):

```go
func (s *SQLite) SetProductEnabled(ctx context.Context, orgID, product string, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org_product (org_id, product, enabled, updated_at)
		 VALUES (?, ?, ?, datetime('now'))
		 ON CONFLICT(org_id, product) DO UPDATE SET enabled=excluded.enabled, updated_at=datetime('now')`,
		orgID, product, e)
	if err != nil {
		return fmt.Errorf("SetProductEnabled: %w", err)
	}
	return nil
}

func (s *SQLite) IsProductEnabled(ctx context.Context, orgID, product string) (bool, error) {
	var enabled int
	err := s.db.QueryRowContext(ctx,
		`SELECT enabled FROM org_product WHERE org_id = ? AND product = ?`, orgID, product).
		Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil // deny-list: no row = enabled
	}
	if err != nil {
		return false, fmt.Errorf("IsProductEnabled: %w", err)
	}
	return enabled == 1, nil
}

func (s *SQLite) ListProductOverrides(ctx context.Context, orgID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT product, enabled FROM org_product WHERE org_id = ?`, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListProductOverrides: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var p string
		var e int
		if err := rows.Scan(&p, &e); err != nil {
			return nil, fmt.Errorf("ListProductOverrides scan: %w", err)
		}
		out[p] = e == 1
	}
	return out, rows.Err()
}
```

> `errors`, `database/sql` (as `sql`), and `fmt` are already imported in `sqlite.go`.

- [ ] **Step 6: Run the test — expect PASS**

Run: `go test ./internal/store/ -run TestProductEntitlement_DenyList -v` → PASS.
Then `go test ./internal/store/` → all PASS (interface satisfied).

- [ ] **Step 7: Commit**

```bash
git add internal/store/schema.sql internal/store/store.go internal/store/sqlite.go internal/store/store_test.go
git commit -m "store: org_product deny-list table + entitlement accessors"
```

---

## Task 2: identity — canonical set, enable/disable, EnabledProducts, create-with-products

**Files:**
- Create: `internal/identity/products.go`
- Test: `internal/identity/products_test.go`

- [ ] **Step 1: Write the failing identity tests**

Create `internal/identity/products_test.go`:

```go
package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newSvc(t *testing.T) (*identity.Service, store.Store) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return identity.New(s), s
}

func TestProducts_DefaultAllEnabled(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")

	m, err := svc.Products(ctx, org.ID)
	if err != nil {
		t.Fatalf("Products: %v", err)
	}
	for _, p := range identity.CanonicalProducts {
		if !m[p] {
			t.Fatalf("default %s should be enabled", p)
		}
	}
	en, _ := svc.EnabledProducts(ctx, org.ID)
	if len(en) != len(identity.CanonicalProducts) {
		t.Fatalf("EnabledProducts default = %v, want all", en)
	}
}

func TestProducts_EnableDisableRoundTrip(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")

	if err := svc.DisableProduct(ctx, org.ID, identity.ProductCairn); err != nil {
		t.Fatalf("DisableProduct: %v", err)
	}
	en, _ := svc.EnabledProducts(ctx, org.ID)
	if got := join(en); got != "ledger,commonplace" {
		t.Fatalf("after disabling cairn, enabled = %q, want ledger,commonplace (canonical order)", got)
	}
	if err := svc.EnableProduct(ctx, org.ID, identity.ProductCairn); err != nil {
		t.Fatalf("EnableProduct: %v", err)
	}
	en, _ = svc.EnabledProducts(ctx, org.ID)
	if got := join(en); got != "cairn,ledger,commonplace" {
		t.Fatalf("after re-enable, enabled = %q", got)
	}
}

func TestProducts_UnknownProduct(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	if err := svc.EnableProduct(ctx, org.ID, "bogus"); !errors.Is(err, identity.ErrUnknownProduct) {
		t.Fatalf("EnableProduct(bogus) err = %v, want ErrUnknownProduct", err)
	}
}

func TestProducts_MissingOrg(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	if err := svc.DisableProduct(ctx, "no-such-org", identity.ProductCairn); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DisableProduct(missing org) err = %v, want ErrNotFound", err)
	}
}

func TestCreateOrgWithProducts_ExplicitSubset(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, err := svc.CreateOrgWithProducts(ctx, "acme", []string{identity.ProductCairn})
	if err != nil {
		t.Fatalf("CreateOrgWithProducts: %v", err)
	}
	m, _ := svc.Products(ctx, org.ID)
	if !m[identity.ProductCairn] || m[identity.ProductLedger] || m[identity.ProductCommonplace] {
		t.Fatalf("subset {cairn} got %+v", m)
	}
}

func TestCreateOrgWithProducts_UnknownNameCreatesNothing(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	if _, err := svc.CreateOrgWithProducts(ctx, "acme", []string{"bogus"}); !errors.Is(err, identity.ErrUnknownProduct) {
		t.Fatalf("err = %v, want ErrUnknownProduct", err)
	}
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/identity/ -run TestProducts -v`
Expected: compile error (`identity.CanonicalProducts` etc. undefined).

- [ ] **Step 3: Implement `products.go`**

Create `internal/identity/products.go`:

```go
package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// Canonical CWB products an org can enable/disable. herald is the core (never
// listed) and interchange is infra. The slice order is the stable claim order.
const (
	ProductCairn       = "cairn"
	ProductLedger      = "ledger"
	ProductCommonplace = "commonplace"
)

// CanonicalProducts is the ordered set of toggleable products.
var CanonicalProducts = []string{ProductCairn, ProductLedger, ProductCommonplace}

// ErrUnknownProduct is returned for a product name outside CanonicalProducts.
var ErrUnknownProduct = errors.New("identity: unknown product")

func isCanonicalProduct(p string) bool {
	for _, c := range CanonicalProducts {
		if c == p {
			return true
		}
	}
	return false
}

// EnableProduct turns a product on for an org.
func (svc *Service) EnableProduct(ctx context.Context, orgID, product string) error {
	return svc.setProduct(ctx, orgID, product, true)
}

// DisableProduct turns a product off for an org (reversible; data untouched).
func (svc *Service) DisableProduct(ctx context.Context, orgID, product string) error {
	return svc.setProduct(ctx, orgID, product, false)
}

func (svc *Service) setProduct(ctx context.Context, orgID, product string, enabled bool) error {
	if !isCanonicalProduct(product) {
		return ErrUnknownProduct
	}
	if _, err := svc.store.GetOrg(ctx, orgID); err != nil {
		return fmt.Errorf("identity.setProduct: org: %w", err)
	}
	return svc.store.SetProductEnabled(ctx, orgID, product, enabled)
}

// GetOrg exposes the store lookup so callers (e.g. adminapi) can verify an org
// exists and get a store.ErrNotFound to map to 404. (Products itself returns an
// all-enabled map for an unknown org, so it cannot be used for existence.)
func (svc *Service) GetOrg(ctx context.Context, orgID string) (store.Org, error) {
	return svc.store.GetOrg(ctx, orgID)
}

// Products returns the full canonical map (product -> enabled), applying the
// deny-list: an absent override row means enabled.
func (svc *Service) Products(ctx context.Context, orgID string) (map[string]bool, error) {
	overrides, err := svc.store.ListProductOverrides(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("identity.Products: %w", err)
	}
	out := make(map[string]bool, len(CanonicalProducts))
	for _, p := range CanonicalProducts {
		enabled, ok := overrides[p]
		if !ok {
			enabled = true // deny-list default
		}
		out[p] = enabled
	}
	return out, nil
}

// EnabledProducts returns the canonical set minus disabled, in canonical order.
func (svc *Service) EnabledProducts(ctx context.Context, orgID string) ([]string, error) {
	m, err := svc.Products(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range CanonicalProducts {
		if m[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// CreateOrgWithProducts creates an org and sets its initial entitlement. A
// nil/empty products slice = all canonical products enabled (writes no rows).
// A non-nil slice enables exactly those; every other canonical product gets an
// explicit disabled row. An unknown name returns ErrUnknownProduct and creates
// no org.
func (svc *Service) CreateOrgWithProducts(ctx context.Context, name string, products []string) (store.Org, error) {
	if products != nil {
		for _, p := range products {
			if !isCanonicalProduct(p) {
				return store.Org{}, ErrUnknownProduct
			}
		}
	}
	org, err := svc.CreateOrg(ctx, name)
	if err != nil {
		return store.Org{}, err
	}
	if products != nil {
		want := map[string]bool{}
		for _, p := range products {
			want[p] = true
		}
		for _, c := range CanonicalProducts {
			if !want[c] {
				if err := svc.store.SetProductEnabled(ctx, org.ID, c, false); err != nil {
					return store.Org{}, fmt.Errorf("CreateOrgWithProducts: disable %s: %w", c, err)
				}
			}
		}
	}
	return org, nil
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/identity/ -run TestProducts -v` and `-run TestCreateOrgWithProducts -v` → PASS.
Then `go test ./internal/identity/` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/products.go internal/identity/products_test.go
git commit -m "identity: canonical product set + enable/disable + EnabledProducts + create-with-products"
```

---

## Task 3: oidc — `products` claim in both grants

**Files:**
- Modify: `internal/oidc/agent_grant.go`
- Modify: `internal/oidc/human_grant.go`
- Test: `internal/oidc/agent_grant_test.go`, `internal/oidc/human_grant_test.go`

> The oidc tests use a real `*identity.Service` as the resolver, so adding `EnabledProducts` to the Service (Task 2) already satisfies the widened interfaces — no test doubles to update.

- [ ] **Step 1: Write the failing claim tests**

In `internal/oidc/agent_grant_test.go`, add a test that mints a token after disabling a product and asserts the `products` claim. Reuse the file's existing mint+decode helpers (it already decodes `claims` from a minted token). Add:

```go
func TestAgentGrant_ProductsClaim(t *testing.T) {
	// Reuse the same setup as the golden-path test: a store, identity.Service,
	// provider+AgentGrant, an org+human+agent, and a signed assertion. Mint a
	// token, then assert claims["products"]. Build it by copying the golden
	// path's arrange section up to the mint, then:
	//   svc.DisableProduct(ctx, org.ID, identity.ProductLedger)
	// BEFORE the mint, and assert the claim excludes ledger.
	// (See TestGoldenPath / the existing mint flow in this file.)
	claims := mintAgentTokenClaims(t) // helper added below wrapping the existing flow
	got := toStringSlice(claims["products"])
	if join(got) != "cairn,commonplace" {
		t.Fatalf("products claim = %v, want [cairn commonplace] after disabling ledger", got)
	}
}

func toStringSlice(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
```

> Concretely: factor the existing golden-path arrange+mint+decode into a small `mintAgentTokenClaims(t)` helper in the test file (org+human+agent+assertion → POST /token → decode claims), call `svc.DisableProduct(ctx, org.ID, "ledger")` before the mint, and return the decoded `claims`. If `join`/`toStringSlice` already exist from another test in the package, don't redeclare them.

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/oidc/ -run TestAgentGrant_ProductsClaim -v`
Expected: FAIL — `claims["products"]` is nil (claim not emitted yet).

- [ ] **Step 3: Widen the resolver + emit the claim (agent)**

In `internal/oidc/agent_grant.go`, add to the `IdentityResolver` interface:

```go
	EnabledProducts(ctx context.Context, orgID string) ([]string, error)
```

In `issue(...)`, after the `scopes, err := g.id.EffectiveScopes(...)` block and before assembling `out`, add:

```go
	products, err := g.id.EnabledProducts(ctx, agent.OrgID)
	if err != nil {
		return "", fmt.Errorf("products: %w", err)
	}
```

Then add `"products": products,` to the `out` map literal (next to `"scope"`).

- [ ] **Step 4: Widen the resolver + emit the claim (human)**

In `internal/oidc/human_grant.go`, add to the `HumanResolver` interface:

```go
	EnabledProducts(ctx context.Context, orgID string) ([]string, error)
```

In `ServeToken`, after `scopes, err := g.id.EffectiveScopes(...)` add:

```go
	products, err := g.id.EnabledProducts(r.Context(), u.OrgID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "login rejected")
		return
	}
```

Then add `"products": products,` to the `SignToken(map[string]any{...})` literal (next to `"scope"`).

- [ ] **Step 5: Add the human claim test**

In `internal/oidc/human_grant_test.go`, mirror the agent test: reuse the existing human-login mint flow, `svc.DisableProduct(ctx, org.ID, "ledger")` before login, decode the token, assert `products` excludes ledger. (Reuse `toStringSlice`/`join` from the agent test file — same package, do not redeclare.)

- [ ] **Step 6: Run — expect PASS**

Run: `go test ./internal/oidc/ -v` → all PASS (golden-path tests still green; new claim tests pass).

- [ ] **Step 7: Commit**

```bash
git add internal/oidc/agent_grant.go internal/oidc/human_grant.go internal/oidc/agent_grant_test.go internal/oidc/human_grant_test.go
git commit -m "oidc: emit products claim in agent + human grants"
```

---

## Task 4: adminapi — product routes + create-org `products`

**Files:**
- Modify: `internal/adminapi/adminapi.go`
- Test: `internal/adminapi/adminapi_test.go`

- [ ] **Step 1: Write the failing adminapi tests**

In `internal/adminapi/adminapi_test.go`, add (reuse the file's existing harness for building an `*API`, an admin token, and issuing requests — match how `TestAdminCreateAgent_*` do it):

```go
func TestAdminProducts_GetEnableDisable(t *testing.T) {
	api, admin := newTestAPI(t) // use the package's existing constructor + admin token
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	org := createOrg(t, srv, admin, "acme") // existing helper or inline POST /api/orgs

	// Default map: all enabled.
	code, body := doJSON(t, srv, admin, "GET", "/api/orgs/"+org+"/products", nil)
	if code != 200 || body["cairn"] != true || body["ledger"] != true || body["commonplace"] != true {
		t.Fatalf("default products GET = %d %+v", code, body)
	}

	// Disable cairn → 200, map shows cairn:false.
	code, body = doJSON(t, srv, admin, "POST", "/api/orgs/"+org+"/products/cairn/disable", nil)
	if code != 200 || body["cairn"] != false {
		t.Fatalf("disable cairn = %d %+v", code, body)
	}

	// Idempotent: disable again still 200.
	code, _ = doJSON(t, srv, admin, "POST", "/api/orgs/"+org+"/products/cairn/disable", nil)
	if code != 200 {
		t.Fatalf("disable cairn (again) = %d, want 200", code)
	}

	// Re-enable.
	code, body = doJSON(t, srv, admin, "POST", "/api/orgs/"+org+"/products/cairn/enable", nil)
	if code != 200 || body["cairn"] != true {
		t.Fatalf("enable cairn = %d %+v", code, body)
	}

	// Unknown product → 400.
	code, _ = doJSON(t, srv, admin, "POST", "/api/orgs/"+org+"/products/bogus/disable", nil)
	if code != 400 {
		t.Fatalf("unknown product = %d, want 400", code)
	}

	// Unknown org → 404.
	code, _ = doJSON(t, srv, admin, "POST", "/api/orgs/no-such/products/cairn/disable", nil)
	if code != 404 {
		t.Fatalf("unknown org = %d, want 404", code)
	}
}

func TestAdminCreateOrg_WithProducts(t *testing.T) {
	api, admin := newTestAPI(t)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	// Create with explicit subset {cairn}.
	code, body := doJSON(t, srv, admin, "POST", "/api/orgs", map[string]any{"name": "acme", "products": []string{"cairn"}})
	if code != 200 {
		t.Fatalf("create org = %d %+v", code, body)
	}
	org, _ := body["id"].(string)

	code, m := doJSON(t, srv, admin, "GET", "/api/orgs/"+org+"/products", nil)
	if code != 200 || m["cairn"] != true || m["ledger"] != false || m["commonplace"] != false {
		t.Fatalf("subset products = %d %+v", code, m)
	}

	// Unknown product in create → 400.
	code, _ = doJSON(t, srv, admin, "POST", "/api/orgs", map[string]any{"name": "x", "products": []string{"bogus"}})
	if code != 400 {
		t.Fatalf("create with bogus product = %d, want 400", code)
	}
}
```

> Adapt `newTestAPI`/`createOrg`/`doJSON` to the file's actual helper names. If the suite lacks a generic JSON helper, write a small one that sets `Authorization: Bearer <admin>` and decodes the JSON body into `map[string]any`.

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./internal/adminapi/ -run 'TestAdminProducts_GetEnableDisable|TestAdminCreateOrg_WithProducts' -v`
Expected: FAIL/404 (routes not registered; `products` ignored on create).

- [ ] **Step 3: Register the routes**

In `internal/adminapi/adminapi.go` `Handler()`, after the `POST /api/orgs/{org}/agents` line add:

```go
	mux.HandleFunc("GET /api/orgs/{org}/products", a.adminOnly(a.handleListProducts))
	mux.HandleFunc("POST /api/orgs/{org}/products/{product}/enable", a.adminOnly(a.handleEnableProduct))
	mux.HandleFunc("POST /api/orgs/{org}/products/{product}/disable", a.adminOnly(a.handleDisableProduct))
```

- [ ] **Step 4: Implement the handlers**

Add to `internal/adminapi/adminapi.go` (near `handleCreateOrg`). Import the `identity` package if not already imported (`"github.com/CarriedWorldUniverse/herald/internal/identity"`).

```go
func (a *API) handleListProducts(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("org")
	if _, err := a.id.GetOrg(r.Context(), orgID); err != nil {
		writeErr(w, http.StatusNotFound, "org not found")
		return
	}
	m, err := a.id.Products(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "products lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (a *API) handleEnableProduct(w http.ResponseWriter, r *http.Request)  { a.setProduct(w, r, true) }
func (a *API) handleDisableProduct(w http.ResponseWriter, r *http.Request) { a.setProduct(w, r, false) }

func (a *API) setProduct(w http.ResponseWriter, r *http.Request, enabled bool) {
	orgID := r.PathValue("org")
	product := r.PathValue("product")
	var err error
	if enabled {
		err = a.id.EnableProduct(r.Context(), orgID, product)
	} else {
		err = a.id.DisableProduct(r.Context(), orgID, product)
	}
	switch {
	case errors.Is(err, identity.ErrUnknownProduct):
		writeErr(w, http.StatusBadRequest, "unknown product")
		return
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "org not found")
		return
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "set product failed")
		return
	}
	m, err := a.id.Products(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "products lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, m)
}
```

> `a.id` is the adminapi's identity service handle (confirm the field name by how `a.id.CreateOrg` is called in `handleCreateOrg`). It must expose `GetOrg`, `Products`, `EnableProduct`, `DisableProduct` — all added to `*identity.Service` in Task 2 (`GetOrg` is the passthrough added there specifically so `handleListProducts` gets a real `store.ErrNotFound` → 404; do NOT use `Products` for existence, since it returns an all-enabled map for an unknown org). If `a.id` is a narrow interface rather than `*identity.Service`, widen that interface to include these methods.

- [ ] **Step 5: Honor `products` on create-org**

In `handleCreateOrg`, change the body struct + create call:

```go
	var body struct {
		Name     string   `json:"name"`
		Products []string `json:"products"`
	}
	if !decode(w, r, &body) {
		return
	}
	org, err := a.id.CreateOrgWithProducts(r.Context(), body.Name, body.Products)
	if err != nil {
		if errors.Is(err, identity.ErrUnknownProduct) {
			writeErr(w, http.StatusBadRequest, "unknown product")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": org.ID, "name": org.Name})
```

> `body.Products` is `nil` when the field is absent (default all-enabled) and a slice when present — exactly the contract `CreateOrgWithProducts` expects.

- [ ] **Step 6: Run — expect PASS**

Run: `go test ./internal/adminapi/ -v` → all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/adminapi/adminapi.go internal/adminapi/adminapi_test.go
git commit -m "adminapi: product list/enable/disable routes + products on create-org"
```

---

## Task 5: heraldauth — parse the `products` claim

**Files:**
- Modify: `heraldauth/heraldauth.go`
- Test: `heraldauth/heraldauth_test.go`

- [ ] **Step 1: Write the failing test**

In `heraldauth/heraldauth_test.go`, add a test that mints (via `liveHerald`) a token whose org has all products and asserts the verified `Identity.Products`. Because `liveHerald` builds an org via `identity.Service`, its agent's token now carries `products`. Add:

```go
func TestVerifier_ParsesProductsClaim(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	v, err := heraldauth.New(context.Background(), heraldauth.Config{Issuer: issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// liveHerald's org enables all products by default.
	want := map[string]bool{"cairn": true, "ledger": true, "commonplace": true}
	got := map[string]bool{}
	for _, p := range id.Products {
		got[p] = true
	}
	for p := range want {
		if !got[p] {
			t.Fatalf("Products = %v, missing %s", id.Products, p)
		}
	}
}
```

> If `liveHerald` returns a different arity, adapt the destructuring; it currently returns `(issuer, agentToken, agentID, humanID, orgID)`.

- [ ] **Step 2: Run — expect FAIL**

Run: `go test ./heraldauth/ -run TestVerifier_ParsesProductsClaim -v`
Expected: FAIL — `id.Products` is empty (not parsed).

- [ ] **Step 3: Add the field + parse**

In `heraldauth/heraldauth.go`:

Add to the `Identity` struct (after `Scopes`):

```go
	Products         []string // CWB products enabled for the org
```

Add to the `tokenClaims` struct (after `Scope`):

```go
	Products []string `json:"products"`
```

In the `Identity{...}` assembly (where `Scopes` is set from `c.Scope`), add after it:

```go
	id.Products = c.Products
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./heraldauth/ -v` → all PASS (incl. the existing `TestVerifier_*`).

- [ ] **Step 5: Full herald suite + commit**

Run: `go test ./... && go vet ./...` (from herald root) → all PASS, vet clean.

```bash
git add heraldauth/heraldauth.go heraldauth/heraldauth_test.go
git commit -m "heraldauth: parse products claim into Identity"
```

---

## Task 6: interchange gateway — enforce product entitlement

**Repo:** `/Users/jacinta/Source/interchange` (create branch `feat/product-entitlement` first).

**Files:**
- Modify: `internal/gateway/gateway.go`
- Test: `internal/gateway/gateway_test.go`
- Modify: `cmd/interchange-gateway/main.go`

- [ ] **Step 0: Branch**

```bash
cd /Users/jacinta/Source/interchange && git checkout main && git pull --ff-only && git checkout -b feat/product-entitlement
```

- [ ] **Step 1: Write the failing gateway tests**

In `internal/gateway/gateway_test.go`, add (reuse the file's existing fake verifier + backend-stub helpers — match how the auth tests build a `Gateway` with a stub `Verifier` and an `httptest` backend):

```go
func TestGateway_DisabledProduct403(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(backend.Close)

	// Verifier returns an identity whose Products do NOT include "cairn".
	g, err := gateway.New(gateway.Config{
		Verifier:      stubVerifier{id: gateway.Identity{Org: "o1", Subject: "s1", Kind: "agent", Products: []string{"ledger"}}},
		Routes:        map[string]string{"/cairn": backend.URL, "/ledger": backend.URL, "/herald": backend.URL},
		RouteProducts: map[string]string{"/cairn": "cairn", "/ledger": "ledger"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)

	// /cairn → 403 (product not enabled).
	if code := getCode(t, srv.URL+"/cairn/x", "tok"); code != 403 {
		t.Fatalf("/cairn = %d, want 403", code)
	}
	// /ledger → 200 (enabled).
	if code := getCode(t, srv.URL+"/ledger/x", "tok"); code != 200 {
		t.Fatalf("/ledger = %d, want 200", code)
	}
	// /herald → 200 (core, no product mapping → always allowed).
	if code := getCode(t, srv.URL+"/herald/x", "tok"); code != 200 {
		t.Fatalf("/herald = %d, want 200", code)
	}
}
```

> Use the package's existing stub verifier type and HTTP helper if present (the auth tests already have one returning a fixed `Identity` / an error). If `getCode`/`stubVerifier` don't exist, add a minimal `stubVerifier{ id Identity; err error }` implementing `Verify`, and a `getCode` that GETs with `Authorization: Bearer <tok>` and returns the status.

- [ ] **Step 2: Run — expect FAIL**

Run: `cd /Users/jacinta/Source/interchange && go test ./internal/gateway/ -run TestGateway_DisabledProduct403 -v`
Expected: compile error (`RouteProducts`/`Identity.Products` undefined).

- [ ] **Step 3: Add `Products` + `RouteProducts` + `route.product` + enforcement**

In `internal/gateway/gateway.go`:

Add to `Identity`:

```go
	Products         []string
```

Add to `Config` (after `Routes`):

```go
	// RouteProducts maps a route prefix → the CWB product gating it (e.g.
	// "/cairn" -> "cairn"). A prefix absent here (e.g. "/herald") is core and
	// never gated. Enforcement: if a matched route has a product and the
	// verified identity's Products does not include it, the request is 403.
	RouteProducts map[string]string
```

Add `product string` to the `route` struct.

Add to `trustedHeaders`:

```go
	"X-CWB-Products",
```

In `New`, when building each `route`, set its product (normalize the prefix the same way, `strings.TrimRight(prefix, "/")`):

```go
		prefix := strings.TrimRight(prefix, "/")
		g.routes = append(g.routes, route{
			prefix:  prefix,
			backend: u,
			proxy:   httputil.NewSingleHostReverseProxy(u),
			product: cfg.RouteProducts[prefix],
		})
```

> Note: the existing loop variable is also named `prefix`; introduce the trimmed local as shown and use it for both the `route.prefix` and the `RouteProducts` lookup so they agree. Keep the rest of the loop identical.

In `serve`, inside the `if !g.bypass && !g.isPublic(...)` block, after `injectIdentity(r, id)`:

```go
		if rt.product != "" && !hasProduct(id.Products, rt.product) {
			http.Error(w, `{"error":"product not enabled for org"}`, http.StatusForbidden)
			return
		}
```

Add a helper and extend `injectIdentity`:

```go
func hasProduct(products []string, p string) bool {
	for _, x := range products {
		if x == p {
			return true
		}
	}
	return false
}
```

In `injectIdentity`, add (so backends can see it; gateway is the enforcer):

```go
	r.Header.Set("X-CWB-Products", strings.Join(id.Products, " "))
```

- [ ] **Step 4: Run — expect PASS**

Run: `go test ./internal/gateway/ -v` → all PASS (existing auth/routing tests still green).

- [ ] **Step 5: Wire the adapter + config**

In `cmd/interchange-gateway/main.go`:

In the `heraldVerifier.Verify` mapping, add `Products: id.Products,` to the returned `gateway.Identity{...}`.

Add a fixed product map constant near the top of the file:

```go
// routeProducts gates each pillar prefix by its CWB product. herald is core
// (absent → never gated). This is stable platform topology, not per-deploy.
var routeProducts = map[string]string{
	"/cairn":     "cairn",
	"/ledger":    "ledger",
	"/knowledge": "commonplace",
}
```

In the `gateway.New(gateway.Config{...})` literal, add `RouteProducts: routeProducts,`.

- [ ] **Step 6: Build + vet + commit**

Run: `go build ./... && go vet ./... && go test ./...` → all PASS.

```bash
git add internal/gateway/gateway.go internal/gateway/gateway_test.go cmd/interchange-gateway/main.go
git commit -m "gateway: enforce per-org product entitlement (403 on disabled product)"
```

---

## Task 7: deploy + conformance (controller / dMon ops)

**Files:** none in-repo besides the conformance check. Commands run over SSH on dMon (`ssh jacinta@100.91.185.71`). "Verification" replaces unit tests.

- [ ] **Step 1: Merge both PRs**

Open + merge the herald PR (`feat/org-product-entitlement` → main) and the interchange PR (`feat/product-entitlement` → main) after CI is green, squash + delete branch. Verify each `mergedAt`.

- [ ] **Step 2: Rebuild + redeploy herald and interchange on dMon**

```bash
ssh jacinta@100.91.185.71 'set -e
  for r in herald interchange; do
    cd ~/src/$r && git checkout main && git pull --ff-only
  done
  cd ~/src/herald && podman build -q -f cmd/herald/Containerfile -t localhost/herald:dev . && podman save localhost/herald:dev | sudo k3s ctr images import -
  # interchange image: use its Containerfile (confirm the path under cmd/interchange-gateway/ or repo root)
  cd ~/src/interchange && podman build -q -f cmd/interchange-gateway/Containerfile -t localhost/interchange-gateway:dev . && podman save localhost/interchange-gateway:dev | sudo k3s ctr images import -
  sudo kubectl rollout restart deploy/herald deploy/interchange-gateway -n cwb
  sudo kubectl rollout status deploy/herald -n cwb --timeout=120s
  sudo kubectl rollout status deploy/interchange-gateway -n cwb --timeout=120s'
```

> Confirm the interchange deployment name (`interchange` vs `interchange-gateway`) and its Containerfile path via `sudo kubectl get deploy -n cwb` and `ls ~/src/interchange/cmd/*/Containerfile` before running; substitute the real names. No DB migration is needed (deny-list = existing orgs stay fully enabled).

- [ ] **Step 3: Add the conformance entitlement check**

In `cwb-conformance`, extend the gateway layer (or add a small `conformance/entitlement` layer following the existing layer pattern): provision an org with cairn **disabled** (admin-direct: `POST /api/orgs` with `{"name":...,"products":["ledger","commonplace"]}` OR create-then-`POST /api/orgs/{id}/products/cairn/disable`), mint an agent token through the gateway, then:
- assert `GET <gateway>/cairn/...` → `403`,
- assert `GET <gateway>/knowledge/...` (an enabled product) → not `403` (200 / its normal code),
- enable cairn (`POST /api/orgs/{id}/products/cairn/enable`), mint a **fresh** token, assert `/cairn/...` is no longer `403`.

Commit + open/merge the conformance PR.

- [ ] **Step 4: Run the full suite against dMon — expect green**

```bash
ssh jacinta@100.91.185.71 'set -e
  cd ~/src/cwb-conformance && git pull -q
  CIP=$(sudo kubectl get svc herald -n cwb -o jsonpath="{.spec.clusterIP}")
  ADMIN=$(sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.admin_token}" | base64 -d)
  CWB_ADMIN_TOKEN="$ADMIN" CWB_HERALD_ADMIN_URL="http://$CIP:8099" CWB_RUN_ID="entitlement-$(date +%s)" \
    go run ./cmd/cwb-conform -target dmon -layers all'
```
Expected: `rc=0`, all layers PASS including the new entitlement assertions.

- [ ] **Step 5: Close out**

Confirm the DoD (spec §7): `org_product` exists, default-all-enabled, admin enable/disable with the documented codes, `products` claim in agent+human tokens, gateway `403` on disabled / proxy on enabled / `/herald` always allowed, all unit suites green, dMon conformance green. File/track follow-up: NEX-402 cross-pillar wipe (the consumer of this registry) is the next cycle.

---

## Notes for the implementer / controller

- **No DB migration.** The deny-list means existing dMon orgs (no `org_product` rows) are fully enabled; only *tokens minted before the redeploy* lack the `products` claim, and the gateway treats a missing claim as no-products (403 on a gated prefix) — but those tokens are short-lived, so a fresh mint after rollout carries the claim. Redeploy herald (mints with claim) and interchange (enforces) together.
- **Helper names:** Tasks 1/2/4/6 say "reuse the existing test helper" — the exact names (`openTestStore`, `newTestAPI`, `doJSON`, `stubVerifier`, `getCode`) are illustrative; match what each test file already defines rather than introducing duplicates.
- **`a.id` surface (Task 4):** the adminapi's identity handle must expose `Products`/`EnableProduct`/`DisableProduct`/`CreateOrgWithProducts` (all added to `*identity.Service` in Task 2) and a way to detect a missing org (404). If it's a narrow interface rather than `*identity.Service`, widen that interface to include the new methods.
- **YAGNI:** no per-product scopes/quotas, no live per-request entitlement lookup at the gateway, no org-owner self-service, no pillar-side re-check of `X-CWB-Products` — all named future work in the spec.
- **Ordering:** Tasks 1→5 are herald and build on each other (store → identity → oidc/adminapi → heraldauth); do them in order. Task 6 (interchange) depends only on the `products` claim existing in tokens (Task 3) and the `heraldauth.Products` field (Task 5) — it can be implemented after Task 5. Task 7 is last.
```
