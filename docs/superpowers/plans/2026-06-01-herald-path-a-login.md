# herald path-A human login (password v0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A human sets a password (admin) and logs in via an OAuth2 password grant at `/token`, receiving a `kind:human` access token — replacing the admin-token stand-in.

**Architecture:** bcrypt the password into the existing `login_secret` column; add a `HumanGrant` to the `/token` endpoint behind a grant dispatcher (`jwt-bearer`→agent, `password`→human); the same provider signs human tokens so consumers are unchanged. Human creation gains optional scopes so a logged-in human can act. Then flip the conformance fixtures + journey to real human login.

**Tech Stack:** Go 1.26, `golang.org/x/crypto/bcrypt`, `zitadel/oidc`-based provider (`go-jose`), modernc sqlite, `net/http`, `testing`/`httptest`.

**Spec:** `docs/2026-06-01-herald-path-a-login-spec.md`

---

## File structure

- **Modify** `internal/store/store.go` — add `SetLoginSecret` to the `Store` interface.
- **Modify** `internal/store/sqlite.go` — implement `SetLoginSecret`.
- **Modify** `internal/identity/identity.go` — `ErrInvalidCredentials`, `SetHumanPassword`, `VerifyHumanPassword` (bcrypt).
- **Modify** `internal/identity/identity_test.go` — password set/verify tests.
- **Create** `internal/oidc/human_grant.go` — `HumanGrant` (password grant) + `HumanResolver`.
- **Create** `internal/oidc/grantmux.go` — `GrantMux` dispatching `/token` by `grant_type`.
- **Create** `internal/oidc/human_grant_test.go` — password-grant + dispatcher tests.
- **Modify** `cmd/herald/main.go` — wire the dispatcher (agent + human grants).
- **Modify** `internal/adminapi/adminapi.go` — `Identity` iface gains `SetHumanPassword`; `POST /api/humans/{id}/password` route + handler; `handleCreateHuman` accepts optional `scopes`.
- **Modify** `internal/adminapi/adminapi_test.go` — password-set + human-scopes tests.
- **(cwb-conformance, Task 4)** `internal/wire/http.go`/new helper, `internal/fixtures/org.go`, `conformance/herald`, `conformance/journey`.

---

## Task 1: store `SetLoginSecret` + identity password set/verify

**Files:**
- Modify: `internal/store/store.go`, `internal/store/sqlite.go`, `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/identity/identity_test.go`:

```go
func TestHumanPassword(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()
	svc := New(s)

	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	h, err := svc.CreateHuman(ctx, org.ID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}

	if err := svc.SetHumanPassword(ctx, h.ID, "correct-horse-battery"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "correct-horse-battery"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, "no-such-user", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify unknown user err = %v, want ErrInvalidCredentials", err)
	}
	// A human with no password set cannot log in.
	h2, _ := svc.CreateHuman(ctx, org.ID, "bob")
	if _, err := svc.VerifyHumanPassword(ctx, h2.ID, "anything"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify no-password err = %v, want ErrInvalidCredentials", err)
	}
}
```

Ensure `identity_test.go` imports `context` and `errors` (add if missing — it already imports `store` and is `package identity`).

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/identity/ -run TestHumanPassword`
Expected: FAIL — `svc.SetHumanPassword`/`VerifyHumanPassword`/`ErrInvalidCredentials` undefined.

- [ ] **Step 3: Add `SetLoginSecret` to the store**

In `internal/store/store.go`, inside the `Store` interface, after `SetUserStatus`:

```go
	SetUserStatus(ctx context.Context, id string, s Status) error
	SetLoginSecret(ctx context.Context, id, hash string) error
```

In `internal/store/sqlite.go`, after the `SetUserStatus` method:

```go
// SetLoginSecret stores a human's password hash (bcrypt) in login_secret.
func (s *SQLite) SetLoginSecret(ctx context.Context, id, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE user SET login_secret = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("SetLoginSecret: %w", err)
	}
	return mustAffect(res)
}
```

(`fmt` and `mustAffect` are already used by `SetUserStatus` in this file.)

- [ ] **Step 4: Add the identity methods**

In `internal/identity/identity.go`, add the bcrypt import (`"golang.org/x/crypto/bcrypt"`) and:

```go
// ErrInvalidCredentials is the single, uniform error every human-login failure
// returns — unknown user, not a human, inactive, no password set, or wrong
// password all look identical, so login leaks no user-enumeration signal.
var ErrInvalidCredentials = errors.New("identity: invalid credentials")

// SetHumanPassword bcrypt-hashes plaintext and stores it as the human's login
// secret. Errors if the user is not a human.
func (svc *Service) SetHumanPassword(ctx context.Context, userID, plaintext string) error {
	u, err := svc.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Kind != store.KindHuman {
		return fmt.Errorf("identity.SetHumanPassword: user %s is not a human", userID)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("identity.SetHumanPassword: hash: %w", err)
	}
	return svc.store.SetLoginSecret(ctx, userID, string(hash))
}

// VerifyHumanPassword returns the user iff it is an active human whose stored
// bcrypt hash matches plaintext. Every failure returns ErrInvalidCredentials.
func (svc *Service) VerifyHumanPassword(ctx context.Context, userID, plaintext string) (store.User, error) {
	u, err := svc.store.GetUser(ctx, userID)
	if err != nil {
		return store.User{}, ErrInvalidCredentials
	}
	if u.Kind != store.KindHuman || u.LoginSecret == "" {
		return store.User{}, ErrInvalidCredentials
	}
	if !svc.IsActive(ctx, userID) {
		return store.User{}, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.LoginSecret), []byte(plaintext)); err != nil {
		return store.User{}, ErrInvalidCredentials
	}
	return u, nil
}
```

(`errors`, `fmt`, `store` are already imported in identity.go.)

- [ ] **Step 5: Run tests**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/identity/ ./internal/store/ && go build ./...`
Expected: PASS, build clean.

- [ ] **Step 6: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/store/store.go internal/store/sqlite.go internal/identity/identity.go internal/identity/identity_test.go
git commit -m "identity: human password set/verify (bcrypt) + store.SetLoginSecret"
```

---

## Task 2: `HumanGrant` + `/token` grant dispatcher

**Files:**
- Create: `internal/oidc/human_grant.go`, `internal/oidc/grantmux.go`
- Modify: `cmd/herald/main.go`
- Test: `internal/oidc/human_grant_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/oidc/human_grant_test.go` (mirrors `agent_grant_test.go`'s `testStack` construction; self-contained — uses only real APIs):

```go
package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// humanStack builds a provider + identity service sharing an in-memory store,
// with the GRANT DISPATCHER (agent + human) wired into /token. Returns the
// service, the test server, and a freshly created org id.
func humanStack(t *testing.T) (*identity.Service, *httptest.Server, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)

	org, err := s.CreateOrg(context.Background(), "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	p, err := herald.NewProvider(herald.Config{Issuer: "https://herald.test/", SigningKey: priv})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.SetTokenHandler(herald.NewGrantMux(herald.NewAgentGrant(p, svc), herald.NewHumanGrant(p, svc)))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return svc, srv, org.ID
}

func TestHumanGrant_PasswordLogin(t *testing.T) {
	ctx := context.Background()
	svc, srv, orgID := humanStack(t)

	h, err := svc.CreateHuman(ctx, orgID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.GrantScope(ctx, h.ID, "issue:write", "admin"); err != nil {
		t.Fatalf("GrantScope: %v", err)
	}
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	// Correct password → kind:human token with org + scope.
	tok := postToken(t, srv.URL, url.Values{
		"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"},
	}, http.StatusOK)
	claims := decodeJWT(t, tok)
	if claims["kind"] != "human" || claims["sub"] != h.ID || claims["org"] != orgID {
		t.Fatalf("claims = %v", claims)
	}
	if sc, _ := claims["scope"].(string); !strings.Contains(sc, "issue:write") {
		t.Fatalf("scope = %v, want issue:write", claims["scope"])
	}

	// Wrong password → 401.
	postToken(t, srv.URL, url.Values{
		"grant_type": {"password"}, "username": {h.ID}, "password": {"nope"},
	}, http.StatusUnauthorized)

	// Unknown grant → 400.
	postToken(t, srv.URL, url.Values{"grant_type": {"client_credentials"}}, http.StatusBadRequest)
}

// postToken POSTs a form to {base}/token, asserts the status, and on 200 returns
// the access_token.
func postToken(t *testing.T, base string, form url.Values, wantStatus int) string {
	t.Helper()
	resp, err := http.PostForm(base+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST /token status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return out.AccessToken
}

// decodeJWT returns the unverified claims of a compact JWT.
func decodeJWT(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return m
}
```

> This is `package oidc_test` (external), same as `agent_grant_test.go`. If `agent_grant_test.go` already defines a `decodeJWT`/`postToken` with the same name in the same package, reuse it instead of redefining (a duplicate in the same package won't compile) — check before adding.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -run TestHumanGrant`
Expected: FAIL — `herald.NewHumanGrant`/`herald.NewGrantMux` undefined.

- [ ] **Step 3: Implement `HumanGrant`**

Create `internal/oidc/human_grant.go`:

```go
package oidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// passwordGrant is the OAuth2 Resource-Owner-Password grant humans use for v0
// login (spec §5b). ROPC is deprecated in OAuth 2.1; acceptable for first-party
// v0, with auth-code + passkey as the hardening path.
const passwordGrant = "password"

// HumanResolver is the slice of the identity service the human grant needs.
type HumanResolver interface {
	VerifyHumanPassword(ctx context.Context, userID, plaintext string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
}

// HumanGrant implements the password token endpoint: a human presents their
// user id + password; herald verifies the bcrypt hash and issues a kind:human
// access token. Mirrors AgentGrant's shape.
type HumanGrant struct {
	p  *Provider
	id HumanResolver
}

// NewHumanGrant wires the grant to a provider + human resolver.
func NewHumanGrant(p *Provider, id HumanResolver) *HumanGrant {
	return &HumanGrant{p: p, id: id}
}

// ServeToken handles POST /token for the password grant.
func (g *HumanGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing username or password")
		return
	}
	u, err := g.id.VerifyHumanPassword(r.Context(), username, password)
	if err != nil {
		// Uniform 401 — never leak which check failed.
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "login rejected")
		return
	}
	scopes, err := g.id.EffectiveScopes(r.Context(), u.ID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "login rejected")
		return
	}
	tok, err := g.p.SignToken(map[string]any{
		"sub":   u.ID,
		"kind":  string(store.KindHuman),
		"org":   u.OrgID,
		"scope": strings.Join(scopes, " "),
	})
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	})
}
```

- [ ] **Step 4: Implement the dispatcher**

Create `internal/oidc/grantmux.go`:

```go
package oidc

import "net/http"

// GrantMux is the POST /token entry point: it routes by grant_type to the agent
// (jwt-bearer) or human (password) grant. Each grant remains a focused unit.
type GrantMux struct {
	agent TokenHandler
	human TokenHandler
}

// NewGrantMux wires the dispatcher. Both args implement TokenHandler.
func NewGrantMux(agent, human TokenHandler) *GrantMux {
	return &GrantMux{agent: agent, human: human}
}

// ServeToken dispatches on grant_type. Parsing here is harmless even though the
// delegate re-parses (ParseForm is idempotent).
func (m *GrantMux) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	switch r.Form.Get("grant_type") {
	case jwtBearerGrant:
		m.agent.ServeToken(w, r)
	case passwordGrant:
		m.human.ServeToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported")
	}
}
```

- [ ] **Step 5: Wire the dispatcher in `cmd/herald/main.go`**

Replace the line `provider.SetTokenHandler(oidc.NewAgentGrant(provider, idsvc))` with:

```go
	provider.SetTokenHandler(oidc.NewGrantMux(
		oidc.NewAgentGrant(provider, idsvc),
		oidc.NewHumanGrant(provider, idsvc),
	))
```

(`idsvc` satisfies both `IdentityResolver` and `HumanResolver` after Task 1.)

- [ ] **Step 6: Run tests**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/oidc/ && go build ./...`
Expected: PASS (the new human-grant test + the existing agent-grant tests, which now route through the dispatcher), build clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/oidc/human_grant.go internal/oidc/grantmux.go internal/oidc/human_grant_test.go cmd/herald/main.go
git commit -m "oidc: password grant (HumanGrant) + /token grant dispatcher"
```

---

## Task 3: adminapi — set-password route + human-create scopes

**Files:**
- Modify: `internal/adminapi/adminapi.go`
- Test: `internal/adminapi/adminapi_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/adminapi/adminapi_test.go` (it already has `adminPost`/`doJSON` helpers + `adminToken` + a `newStack`-style setup from the by-fingerprint work — mirror them):

```go
func TestHumanPasswordAndScopes(t *testing.T) {
	_, _, srv := newStack(t) // returns (svc, provider, httptest server) — mirror existing setup
	// org
	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)

	// create a human WITH scopes
	_, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans",
		map[string]any{"display_name": "alice", "scopes": []string{"issue:read", "issue:write"}})
	humanID, _ := human["id"].(string)
	if humanID == "" {
		t.Fatalf("no human id: %v", human)
	}

	// set a password
	resp, _ := adminPost(t, srv.URL+"/api/humans/"+humanID+"/password", map[string]any{"password": "hunter2hunter2"})
	if resp.StatusCode != 200 {
		t.Fatalf("set password: %d", resp.StatusCode)
	}

	// too-short password → 400
	resp, _ = adminPost(t, srv.URL+"/api/humans/"+humanID+"/password", map[string]any{"password": "x"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short password = %d, want 400", resp.StatusCode)
	}

	// no admin token → 401
	resp, _ = doJSON(t, "POST", srv.URL+"/api/humans/"+humanID+"/password", "", map[string]any{"password": "hunter2hunter2"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token = %d, want 401", resp.StatusCode)
	}
}
```

> Match the exact return signature of the existing test setup helper (`newStack`/`newTestAPI` — whatever `adminapi_test.go` already defines) and the `adminPost`/`doJSON` helper shapes. Do not invent new helpers; reuse the file's.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/adminapi/ -run TestHumanPasswordAndScopes`
Expected: FAIL — route 404 / scopes ignored.

- [ ] **Step 3: Extend the `Identity` interface**

In `internal/adminapi/adminapi.go`, add to the `Identity` interface (alongside `CreateHuman`, `GrantScope`):

```go
	SetHumanPassword(ctx context.Context, userID, plaintext string) error
```

- [ ] **Step 4: Add the password route + handler**

Register the route in the mux (next to the other `/api/humans` routes):

```go
	mux.HandleFunc("POST /api/humans/{id}/password", a.adminOnly(a.handleSetHumanPassword))
```

Add the handler:

```go
// handleSetHumanPassword sets a human's login password (admin-gated). bcrypt
// hashing lives in the identity layer.
func (a *API) handleSetHumanPassword(w http.ResponseWriter, r *http.Request) {
	humanID := r.PathValue("id")
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if err := a.id.SetHumanPassword(r.Context(), humanID, body.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}
```

- [ ] **Step 5: Accept optional `scopes` on human creation**

Replace `handleCreateHuman` so it grants optional scopes after creating the human:

```go
func (a *API) handleCreateHuman(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("org")
	var body struct {
		DisplayName string   `json:"display_name"`
		Scopes      []string `json:"scopes"`
	}
	if !decode(w, r, &body) {
		return
	}
	h, err := a.id.CreateHuman(r.Context(), orgID, body.DisplayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, sc := range body.Scopes {
		if err := a.id.GrantScope(r.Context(), h.ID, sc, "admin"); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": h.ID, "display_name": h.DisplayName, "org": h.OrgID})
}
```

- [ ] **Step 6: Run tests**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/adminapi/ && go build ./... && go vet ./...`
Expected: PASS, build + vet clean.

- [ ] **Step 7: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/adminapi/adminapi.go internal/adminapi/adminapi_test.go
git commit -m "adminapi: POST /api/humans/{id}/password + optional scopes on human create"
```

---

## Task 4: deploy + conformance close-the-loop

**Files:**
- (herald) PR + merge `feat/path-a-login`; redeploy on dMon.
- (cwb-conformance) `internal/wire/` (a `LoginHuman` helper), `internal/fixtures/org.go`, `conformance/herald`, `conformance/journey`.

- [ ] **Step 1: Open + merge the herald PR; redeploy**

```bash
cd /Users/jacinta/Source/herald && git push -u origin feat/path-a-login
gh pr create --base main --title "herald: path-A human login (password grant)" --body "Implements docs/2026-06-01-herald-path-a-login-spec.md."
# wait for CI green, then merge --squash --delete-branch
ssh jacinta@100.91.185.71 'cd ~/src/herald && git checkout main && git pull \
  && podman build -q -f cmd/herald/Containerfile -t localhost/herald:dev . \
  && podman save localhost/herald:dev | sudo k3s ctr images import - \
  && sudo kubectl rollout restart deployment/herald -n cwb \
  && sudo kubectl rollout status deployment/herald -n cwb --timeout=120s'
```

- [ ] **Step 2: Add a `LoginHuman` wire helper (cwb-conformance)**

In `cwb-conformance` `internal/wire/`, add (e.g. to `mint.go` or a new `login.go`):

```go
// LoginHuman performs the password grant: POST /token with grant_type=password,
// returning the human's access token. Mirrors MintAgentToken.
func LoginHuman(ctx context.Context, tokenURL, userID, password string) (string, error) {
	form := url.Values{"grant_type": {"password"}, "username": {userID}, "password": {password}}
	resp, body, err := PostForm(ctx, tokenURL, form, nil)
	if err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("login: status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("login: decode: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("login: empty access_token: %s", body)
	}
	return out.AccessToken, nil
}
```

(Imports: `context`, `encoding/json`, `fmt`, `net/url` — match the file you add it to.)

- [ ] **Step 3: Flip fixtures to real human login**

In `cwb-conformance` `internal/fixtures/org.go`, replace the human-provisioning loop (the one that mints via `POST /api/humans/{id}/token`) with create → set-password → password-grant login. alice gets issue scopes:

```go
	// 2. Create humans, set a password, and log in via the REAL password grant
	//    (path-A) — replacing the admin-token stand-in.
	for _, name := range []string{"alice", "bob"} {
		createBody := map[string]any{"display_name": name}
		if name == "alice" {
			createBody["scopes"] = []string{"issue:read", "issue:write"}
		}
		var h struct {
			ID string `json:"id"`
		}
		mustJSON(t, ctx, fmt.Sprintf("%s/api/orgs/%s/humans", base, org.OrgID), tgt.AdminToken, createBody, &h)

		pw := "pw-" + tgt.RunID + "-" + name
		resp, raw, err := wire.PostJSON(ctx, fmt.Sprintf("%s/api/humans/%s/password", base, h.ID), tgt.AdminToken,
			map[string]any{"password": pw})
		if err != nil {
			t.Fatalf("set password for %s: %v", name, err)
		}
		if resp.StatusCode/100 != 2 {
			t.Fatalf("set password for %s: status %d: %s", name, resp.StatusCode, raw)
		}
		token, err := wire.LoginHuman(ctx, tgt.TokenURL(), h.ID, pw)
		if err != nil {
			t.Fatalf("login %s: %v", name, err)
		}
		org.Humans[name] = Principal{ID: h.ID, Kind: "human", Token: token}
	}
```

`base` here is `tgt.HeraldAdminBase()` (admin endpoints are admin-direct, as the org/agent admin calls already are in this function); the password-grant login uses `tgt.TokenURL()` (gateway-fronted, public). Keep `mustJSON` for the create call (it already posts with the admin token). `wire.PostJSON` returns a nil `resp` only alongside a non-nil `err`, so the err-check precedes the status-check.

- [ ] **Step 4: herald conformance layer — assert human login**

In `cwb-conformance` `conformance/herald/herald_test.go`, the org's humans are now provisioned by real login, so add a subtest asserting the human token is real:

```go
	t.Run("HumanLoginToken", func(t *testing.T) {
		alice, ok := org.Humans["alice"]
		if !ok || alice.Token == "" {
			t.Fatal("alice has no login token")
		}
		claims, err := wire.DecodeClaims(alice.Token)
		if err != nil {
			t.Fatalf("decode alice token: %v", err)
		}
		if claims["kind"] != "human" || claims["sub"] != alice.ID {
			t.Fatalf("alice claims = %v (want kind:human, sub=%s)", claims, alice.ID)
		}
	})
```

(Add this `t.Run` inside the existing `TestHeraldLayer`, alongside the others.)

- [ ] **Step 5: journey reviewer becomes a real human**

In `cwb-conformance` `conformance/journey/journey_test.go`:
- In `setupLedger`, also register alice as a ledger user with `kind:"human"` + org member (alongside admin/builder/reader). The simplest is to add `"alice"` handling: register `org.Humans["alice"].ID` as a ledger user `{id, kind:"human"}` and add it as a member.
- In the review step (the comment + `In Review`/`Done` transitions), use `org.Humans["alice"].Token` instead of `admin.Token`. Update the log line to say the reviewer is a human (alice).

Concretely, in `setupLedger` add after the agent loop:

```go
	alice := org.Humans["alice"]
	if resp, raw := lpost(t, base+"/api/admin/users", admin.Token, map[string]any{"id": alice.ID, "kind": "human"}); resp.StatusCode/100 != 2 {
		t.Fatalf("create ledger user alice = %d: %s", resp.StatusCode, raw)
	}
	if resp, raw := lpost(t, base+"/api/admin/orgs/"+org.OrgID+"/members", admin.Token, map[string]any{"user_id": alice.ID, "role": "member"}); resp.StatusCode/100 != 2 {
		t.Fatalf("add member alice = %d: %s", resp.StatusCode, raw)
	}
```

(`base` in `setupLedger` is `tgt.LedgerBase()`; `admin` is `org.Agents["admin"]` — both already in scope there.)

And change the review block to use `alice := org.Humans["alice"]` / `alice.Token`:

```go
	alice := org.Humans["alice"]
	if resp, raw := lpost(t, tgt.LedgerBase()+"/api/issues/"+issueKey+"/comments", alice.Token,
		map[string]any{"body": "Reviewed the feature branch — LGTM."}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("review comment = %d: %s", resp.StatusCode, raw)
	}
	transition(t, tgt, alice.Token, issueKey, "In Review")
	transition(t, tgt, alice.Token, issueKey, "Done")
	t.Log("ledger: reviewer alice (REAL human login) commented + transitioned to Done")
```

(`alice` is now declared in both `setupLedger` and the test body; ensure no duplicate declaration in the same scope — the one in the review block is in `TestJourneyLayer`, the one in `setupLedger` is a separate function, so both are fine.) Drop the now-unused `admin` reference in the review block if it leaves `admin` unused in the test body — it's still used elsewhere (it's `org.Agents["admin"]`, used for setup via `setupLedger`), so no unused-var issue.

- [ ] **Step 6: Run the suite against dMon**

```bash
ssh jacinta@100.91.185.71 'cd ~/src/cwb-conformance && git pull \
  && CIP=$(sudo kubectl get svc herald -n cwb -o jsonpath="{.spec.clusterIP}") \
  && ADMIN=$(sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.admin_token}" | base64 -d) \
  && CWB_ADMIN_TOKEN="$ADMIN" CWB_HERALD_ADMIN_URL="http://$CIP:8099" CWB_RUN_ID="pa$(date +%s)" \
     go run ./cmd/cwb-conform -target dmon -layers all'
```
Expected: all 6 layers green; the journey log shows the reviewer is alice (real human login).

- [ ] **Step 7: Commit + PR (cwb-conformance)**

```bash
cd /Users/jacinta/Source/cwb-conformance
git add internal/wire/ internal/fixtures/org.go conformance/herald/ conformance/journey/
git commit -m "conformance: real human login (path-A) — fixtures + journey reviewer = alice"
```

---

## Notes for the implementer

- **Uniform 401:** every human-login failure returns `ErrInvalidCredentials` → `401 invalid_grant`. Do not add detail that distinguishes unknown-user from wrong-password.
- **The dispatcher must not break agents:** after Task 2, the existing agent jwt-bearer tests run THROUGH `GrantMux` — they must still pass. If they don't, the dispatcher routing or double-`ParseForm` is the suspect.
- **Username = user id** (UUID) for v0; email/login-name is future.
- **bcrypt** is `golang.org/x/crypto/bcrypt` (already in `go.sum`; `go mod tidy` may promote it to a direct require — that's fine).
- **YAGNI:** no passkey, no auth-code/login page, no password reset/lockout, no email username — all named future work in the spec.
- **Test-helper reuse:** Tasks 2 + 3 test files must reuse the EXISTING construction idioms in `agent_grant_test.go` / `adminapi_test.go` (provider/stack setup, `adminPost`/`doJSON`). The plan's test bodies fix the assertions; the setup must match what's already there.
