# herald Refresh Tokens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** herald issues a rotating refresh token on every token grant and accepts a `refresh_token` grant + an RFC 7009 `/revoke` endpoint, so clients (the `cw` CLI) can keep a session alive across the 10-minute access-token TTL without re-presenting a password or re-minting an assertion.

**Architecture:** A new `refresh_token` table persists opaque `"<id>.<secret>"` tokens (only the secret's SHA-256 is stored). Both existing grants (`password`, `jwt-bearer`) additionally mint a refresh token. A new `RefreshGrant` validates a presented refresh token, **rebuilds the access-token claims from the user record** (so scope/product changes take effect), and **rotates** — revoking the whole chain and issuing a fresh successor; reuse of a revoked token revokes the chain (replay defense). `/revoke` kills a chain. All of these are tokenless auth-routes (the refresh token / assertion / password is the credential), reached through interchange's existing unauthenticated `/herald` bootstrap lane.

**Tech Stack:** Go 1.26, `modernc.org/sqlite`, `go-jose/v4` (already in use), `crypto/rand` + `crypto/sha256` + `crypto/subtle`.

This is sub-project **#0a** of the CW CLI suite. Spec: `cw/docs/superpowers/specs/2026-06-02-cw-core-auth-design.md` (Part A). The `cw` core+auth plan (#0b) consumes this and is a separate cycle; build + deploy this first.

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `internal/store/schema.sql` | `refresh_token` table | Modify |
| `internal/store/store.go` | `RefreshToken` type + 3 interface methods | Modify |
| `internal/store/sqlite.go` | sqlite impl of the 3 methods + DeleteOrg cascade | Modify |
| `internal/store/sqlite_test.go` | store-level refresh-token tests | Modify (or create if absent) |
| `internal/oidc/claims.go` | shared `accessClaims` builder (human + agent) | Create |
| `internal/oidc/refresh.go` | `RefreshStore`, `RefreshIssuer`, `RefreshGrant`, helpers | Create |
| `internal/oidc/refresh_test.go` | refresh issuer/grant/revoke tests | Create |
| `internal/oidc/agent_grant.go` | use `accessClaims`; attach refresh token | Modify |
| `internal/oidc/human_grant.go` | use `accessClaims`; attach refresh token; take `IdentityResolver` | Modify |
| `internal/oidc/grantmux.go` | route `refresh_token` | Modify |
| `internal/oidc/provider.go` | `POST /revoke`; discovery advertises refresh + revoke | Modify |
| `cmd/herald/main.go` | build `RefreshIssuer`, wire grants + revoke | Modify |
| `interchange` herald composite | `/herald/revoke` tokenless passthrough | Modify (Task 6) |
| `cwb-conformance` herald layer | issue→refresh→use→revoke flow | Modify (Task 7) |

---

## Task 1: store — `refresh_token` persistence

**Files:**
- Modify: `internal/store/schema.sql`
- Modify: `internal/store/store.go`
- Modify: `internal/store/sqlite.go`
- Test: `internal/store/sqlite_test.go`

- [ ] **Step 1: Add the table + index to the schema**

Append to `internal/store/schema.sql`:

```sql
-- Refresh tokens (rotating). The opaque token handed to a client is
-- "<id>.<secret>"; only sha256(secret) is stored. chain_id groups a rotation
-- lineage so the whole chain can be revoked (logout, or replay of a rotated
-- token). A row is valid when revoked_at IS NULL and expires_at is in future.
CREATE TABLE IF NOT EXISTS refresh_token (
  id          TEXT PRIMARY KEY,                 -- public handle (random hex)
  chain_id    TEXT NOT NULL,                    -- rotation-lineage root id
  token_hash  TEXT NOT NULL,                    -- hex sha256 of the secret
  user_id     TEXT NOT NULL REFERENCES user(id),
  issued_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,                    -- RFC3339 (UTC)
  revoked_at  TEXT                              -- NULL until revoked
);
CREATE INDEX IF NOT EXISTS idx_refresh_chain ON refresh_token(chain_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user  ON refresh_token(user_id);
```

- [ ] **Step 2: Add the type + interface methods**

In `internal/store/store.go`, add the type after `ScopeGrant`:

```go
// RefreshToken is a persisted, rotating refresh token. The plaintext secret is
// never stored — only TokenHash (hex sha256). RevokedAt is empty when live.
type RefreshToken struct {
	ID        string
	ChainID   string
	TokenHash string
	UserID    string
	IssuedAt  string
	ExpiresAt string // RFC3339 UTC
	RevokedAt string // empty == not revoked
}
```

And add to the `Store` interface, after the Scopes block:

```go
	// Refresh tokens (rotating; see RefreshToken).
	CreateRefreshToken(ctx context.Context, rt RefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (RefreshToken, error)
	// RevokeRefreshChain marks every still-live row in the chain revoked.
	// Idempotent.
	RevokeRefreshChain(ctx context.Context, chainID string) error
```

- [ ] **Step 3: Write the failing store test**

In `internal/store/sqlite_test.go` add (create the file with `package store` + imports `context`, `testing`, `time` if it does not exist):

```go
func TestRefreshToken_CreateGetRevokeChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindHuman, DisplayName: "alice"})

	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	rt := RefreshToken{ID: "h1", ChainID: "h1", TokenHash: "hash1", UserID: u.ID, ExpiresAt: exp}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	got, err := s.GetRefreshToken(ctx, "h1")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if got.UserID != u.ID || got.ChainID != "h1" || got.TokenHash != "hash1" || got.RevokedAt != "" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// A successor in the same chain.
	if err := s.CreateRefreshToken(ctx, RefreshToken{ID: "h2", ChainID: "h1", TokenHash: "hash2", UserID: u.ID, ExpiresAt: exp}); err != nil {
		t.Fatalf("create successor: %v", err)
	}
	if err := s.RevokeRefreshChain(ctx, "h1"); err != nil {
		t.Fatalf("RevokeRefreshChain: %v", err)
	}
	for _, id := range []string{"h1", "h2"} {
		g, _ := s.GetRefreshToken(ctx, id)
		if g.RevokedAt == "" {
			t.Fatalf("token %s should be revoked after chain revoke", id)
		}
	}

	if _, err := s.GetRefreshToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing token err = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 4: Run it — expect FAIL (methods undefined)**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestRefreshToken -v`
Expected: compile error / FAIL — `CreateRefreshToken` undefined.

- [ ] **Step 5: Implement the three methods**

In `internal/store/sqlite.go` (after the scope methods):

```go
func (s *SQLite) CreateRefreshToken(ctx context.Context, rt RefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO refresh_token (id, chain_id, token_hash, user_id, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		rt.ID, rt.ChainID, rt.TokenHash, rt.UserID, rt.ExpiresAt)
	if err != nil {
		return fmt.Errorf("CreateRefreshToken: %w", err)
	}
	return nil
}

func (s *SQLite) GetRefreshToken(ctx context.Context, id string) (RefreshToken, error) {
	var rt RefreshToken
	var revoked sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, chain_id, token_hash, user_id, issued_at, expires_at, revoked_at
		   FROM refresh_token WHERE id = ?`, id).
		Scan(&rt.ID, &rt.ChainID, &rt.TokenHash, &rt.UserID, &rt.IssuedAt, &rt.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, fmt.Errorf("GetRefreshToken: %w", err)
	}
	rt.RevokedAt = revoked.String
	return rt, nil
}

func (s *SQLite) RevokeRefreshChain(ctx context.Context, chainID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_token SET revoked_at = datetime('now')
		   WHERE chain_id = ? AND revoked_at IS NULL`, chainID)
	if err != nil {
		return fmt.Errorf("RevokeRefreshChain: %w", err)
	}
	return nil
}
```

- [ ] **Step 6: Extend the DeleteOrg cascade**

In `internal/store/sqlite.go`, inside `DeleteOrg`, add this BEFORE the `DELETE FROM user` statement (refresh_token.user_id is an FK to user):

```go
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM refresh_token WHERE user_id IN (SELECT id FROM user WHERE org_id=?)`, id); err != nil {
		return fmt.Errorf("DeleteOrg: refresh_token: %w", err)
	}
```

- [ ] **Step 7: Run the store tests — expect PASS**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/store/ -v`
Expected: PASS (including `TestRefreshToken_CreateGetRevokeChain` and the existing DeleteOrg tests).

- [ ] **Step 8: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/store/
git commit -m "store: persist rotating refresh tokens (refresh_token table + DeleteOrg cascade)"
```

---

## Task 2: oidc — shared `accessClaims` builder (pure refactor)

The refresh grant must reproduce **exactly** the access-token claims the original grant would, re-derived from the user record. Extract the assembly into one helper used by the agent, human, and (next task) refresh grants, so there is a single source of truth.

**Files:**
- Create: `internal/oidc/claims.go`
- Modify: `internal/oidc/agent_grant.go`
- Modify: `internal/oidc/human_grant.go`
- Modify: `cmd/herald/main.go`

- [ ] **Step 1: Create the shared builder**

`internal/oidc/claims.go`:

```go
package oidc

import (
	"context"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// accessClaims assembles the access-token claim set for a user FROM THE RECORD
// (never from client input). Humans get sub/kind/org/scope/products; agents
// additionally get agent_fp + act.sub (responsible human) + human_fp. This is
// the single source of truth shared by the agent, human, and refresh grants.
func accessClaims(ctx context.Context, id IdentityResolver, u store.User) (map[string]any, error) {
	scopes, err := id.EffectiveScopes(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	products, err := id.EnabledProducts(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"sub":      u.ID,
		"kind":     string(u.Kind),
		"org":      u.OrgID,
		"scope":    strings.Join(scopes, " "),
		"products": products,
	}
	if u.Kind == store.KindAgent {
		out["agent_fp"] = u.CasketFingerprint
		if u.ResponsibleHuman != "" {
			out["act"] = map[string]any{"sub": u.ResponsibleHuman}
			if human, err := id.GetUser(ctx, u.ResponsibleHuman); err == nil && human.CasketFingerprint != "" {
				out["human_fp"] = human.CasketFingerprint
			}
		}
	}
	return out, nil
}
```

- [ ] **Step 2: Refactor `AgentGrant.issue` step 6 to use it**

In `internal/oidc/agent_grant.go`, replace the claim-assembly block (everything from `scopes, err := g.id.EffectiveScopes(ctx, agent.ID)` through the final `return g.p.SignToken(out)`) with:

```go
	out, err := accessClaims(ctx, g.id, agent)
	if err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	return g.p.SignToken(out)
```

(The `IsActive` block above it stays unchanged.)

- [ ] **Step 3: Widen `HumanGrant` to `IdentityResolver` + use the builder**

In `internal/oidc/human_grant.go`:

Replace the `HumanResolver` interface with a small one that embeds verification + the resolver:

```go
// HumanResolver is the slice of the identity service the human grant needs:
// password verification plus the shared claim-building resolver.
type HumanResolver interface {
	VerifyHumanPassword(ctx context.Context, userID, plaintext string) (store.User, error)
	IdentityResolver
}
```

Replace the body from `scopes, err := g.id.EffectiveScopes(...)` through the `tok, err := g.p.SignToken(...)` block with:

```go
	claims, err := accessClaims(r.Context(), g.id, u)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "login rejected")
		return
	}
	tok, err := g.p.SignToken(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
```

Remove the now-unused `strings` import if the linter flags it.

> `IdentityResolver` (in `agent_grant.go`) declares `GetUser`, `EffectiveScopes`, `IsActive`, `EnabledProducts`. `*identity.Service` already satisfies it, so the `main.go` wiring (`NewHumanGrant(provider, idsvc)`) is unchanged.

- [ ] **Step 4: Run the oidc tests — expect PASS (behavior unchanged)**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -v`
Expected: PASS — `TestVerifyHumanPassword*`, agent-grant and human-grant tests still green (claims are byte-identical to before).

- [ ] **Step 5: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/oidc/claims.go internal/oidc/agent_grant.go internal/oidc/human_grant.go
git commit -m "oidc: extract shared accessClaims builder (no behavior change)"
```

---

## Task 3: oidc — `RefreshIssuer` + attach a refresh token to both grants

**Files:**
- Create: `internal/oidc/refresh.go`
- Create: `internal/oidc/refresh_test.go`
- Modify: `internal/oidc/agent_grant.go`, `internal/oidc/human_grant.go`
- Modify: `cmd/herald/main.go`

- [ ] **Step 1: Create the refresh issuer + helpers**

`internal/oidc/refresh.go`:

```go
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// refreshTokenGrant is the OAuth2 refresh grant type.
const refreshTokenGrant = "refresh_token"

// defaultRefreshTTL bounds a refresh token's life (overridable via NewRefreshIssuer).
const defaultRefreshTTL = 720 * time.Hour // 30 days

// RefreshStore is the persistence slice the refresh machinery needs.
type RefreshStore interface {
	CreateRefreshToken(ctx context.Context, rt store.RefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (store.RefreshToken, error)
	RevokeRefreshChain(ctx context.Context, chainID string) error
}

// RefreshIssuer mints, validates, rotates, and revokes refresh tokens. The
// opaque token is "<id>.<secret>"; only sha256(secret) is persisted.
type RefreshIssuer struct {
	p   *Provider
	st  RefreshStore
	ttl time.Duration
}

// NewRefreshIssuer wires the issuer to a provider + store. ttl<=0 uses the default.
func NewRefreshIssuer(p *Provider, st RefreshStore, ttl time.Duration) *RefreshIssuer {
	if ttl <= 0 {
		ttl = defaultRefreshTTL
	}
	return &RefreshIssuer{p: p, st: st, ttl: ttl}
}

// Issue mints a NEW chain (chain_id == the token id) for userID and returns the
// opaque "<id>.<secret>".
func (ri *RefreshIssuer) Issue(ctx context.Context, userID string) (string, error) {
	id := randHex(16)
	return ri.persist(ctx, userID, id, id)
}

// rotate revokes the presented token's chain and issues a fresh successor in
// the same chain. Because the chain is revoked first and the successor is
// inserted after (revoked_at NULL), only the newest token is ever live.
func (ri *RefreshIssuer) rotate(ctx context.Context, old store.RefreshToken) (string, error) {
	if err := ri.st.RevokeRefreshChain(ctx, old.ChainID); err != nil {
		return "", err
	}
	return ri.persist(ctx, old.UserID, randHex(16), old.ChainID)
}

func (ri *RefreshIssuer) persist(ctx context.Context, userID, id, chainID string) (string, error) {
	secret := randB64(32)
	exp := ri.p.now().Add(ri.ttl).UTC().Format(time.RFC3339)
	if err := ri.st.CreateRefreshToken(ctx, store.RefreshToken{
		ID: id, ChainID: chainID, TokenHash: sha256hex(secret), UserID: userID, ExpiresAt: exp,
	}); err != nil {
		return "", err
	}
	return id + "." + secret, nil
}

// validate resolves a presented refresh token to its live row, or errors.
// Reuse of a revoked (rotated) token revokes the whole chain (replay defense).
func (ri *RefreshIssuer) validate(ctx context.Context, presented string) (store.RefreshToken, error) {
	id, secret, ok := splitRefresh(presented)
	if !ok {
		return store.RefreshToken{}, errors.New("malformed refresh token")
	}
	rt, err := ri.st.GetRefreshToken(ctx, id)
	if err != nil {
		return store.RefreshToken{}, err
	}
	if subtle.ConstantTimeCompare([]byte(rt.TokenHash), []byte(sha256hex(secret))) != 1 {
		return store.RefreshToken{}, errors.New("refresh secret mismatch")
	}
	if rt.RevokedAt != "" {
		_ = ri.st.RevokeRefreshChain(ctx, rt.ChainID) // replay: kill the chain
		return store.RefreshToken{}, errors.New("refresh token revoked")
	}
	exp, err := time.Parse(time.RFC3339, rt.ExpiresAt)
	if err != nil || ri.p.now().After(exp) {
		return store.RefreshToken{}, errors.New("refresh token expired")
	}
	return rt, nil
}

// revoke kills the chain of a presented token. Best-effort + idempotent: an
// unknown/garbage token is a silent no-op (no enumeration).
func (ri *RefreshIssuer) revoke(ctx context.Context, presented string) {
	id, _, ok := splitRefresh(presented)
	if !ok {
		return
	}
	if rt, err := ri.st.GetRefreshToken(ctx, id); err == nil {
		_ = ri.st.RevokeRefreshChain(ctx, rt.ChainID)
	}
}

func splitRefresh(s string) (id, secret string, ok bool) {
	i := strings.IndexByte(s, '.')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}
```

- [ ] **Step 2: Write the failing issuer test**

`internal/oidc/refresh_test.go`:

```go
package oidc

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newRefreshStack(t *testing.T) (*RefreshIssuer, *store.SQLite, store.User) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	org, _ := st.CreateOrg(context.Background(), "acme")
	u, _ := st.CreateUser(context.Background(), store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, err := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return NewRefreshIssuer(p, st, 0), st, u
}

func TestRefreshIssuer_IssueValidateRotate(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)

	tok1, err := ri.Issue(ctx, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rt, err := ri.validate(ctx, tok1)
	if err != nil {
		t.Fatalf("validate fresh: %v", err)
	}
	if rt.UserID != u.ID {
		t.Fatalf("user = %q, want %q", rt.UserID, u.ID)
	}

	tok2, err := ri.rotate(ctx, rt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := ri.validate(ctx, tok2); err != nil {
		t.Fatalf("validate rotated successor: %v", err)
	}
	// The OLD token is now revoked, and reusing it must revoke the chain so the
	// successor also dies (replay defense).
	if _, err := ri.validate(ctx, tok1); err == nil {
		t.Fatal("reused (rotated-away) token must be rejected")
	}
	if _, err := ri.validate(ctx, tok2); err == nil {
		t.Fatal("replay of the old token must revoke the whole chain (successor dead)")
	}
}

func TestRefreshIssuer_RevokeAndGarbage(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)
	tok, _ := ri.Issue(ctx, u.ID)
	ri.revoke(ctx, tok)
	if _, err := ri.validate(ctx, tok); err == nil {
		t.Fatal("revoked token must be rejected")
	}
	ri.revoke(ctx, "garbage-no-dot") // must not panic
	if _, err := ri.validate(ctx, "garbage-no-dot"); err == nil {
		t.Fatal("malformed token must be rejected")
	}
}
```

- [ ] **Step 3: Run — expect PASS**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -run TestRefreshIssuer -v`
Expected: PASS.

- [ ] **Step 4: Attach a refresh token to the human grant response**

In `internal/oidc/human_grant.go`: add a `refresh *RefreshIssuer` field + constructor param, and emit `refresh_token`.

Change the struct + constructor:

```go
type HumanGrant struct {
	p       *Provider
	id      HumanResolver
	refresh *RefreshIssuer
}

func NewHumanGrant(p *Provider, id HumanResolver, refresh *RefreshIssuer) *HumanGrant {
	return &HumanGrant{p: p, id: id, refresh: refresh}
}
```

Replace the final `writeJSON(...)` block with:

```go
	resp := map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	}
	if g.refresh != nil {
		if rtok, err := g.refresh.Issue(r.Context(), u.ID); err == nil {
			resp["refresh_token"] = rtok
		}
	}
	writeJSON(w, http.StatusOK, resp)
```

- [ ] **Step 5: Attach a refresh token to the agent grant response**

In `internal/oidc/agent_grant.go`: the agent id is needed for `Issue`. Change `issue` to also return the agent id, and emit `refresh_token`.

Struct + constructor:

```go
type AgentGrant struct {
	p       *Provider
	id      IdentityResolver
	refresh *RefreshIssuer
}

func NewAgentGrant(p *Provider, id IdentityResolver, refresh *RefreshIssuer) *AgentGrant {
	return &AgentGrant{p: p, id: id, refresh: refresh}
}
```

Change `issue` signature to `func (g *AgentGrant) issue(...) (token, subject string, err error)`: return `"", "", err` on every error path, and on success `return tok, agent.ID, nil` (the final return becomes:)

```go
	signed, err := g.p.SignToken(out)
	if err != nil {
		return "", "", err
	}
	return signed, agent.ID, nil
```

In `ServeToken`, replace the `tok, err := g.issue(...)` + success `writeJSON` with:

```go
	tok, subject, err := g.issue(r.Context(), assertion, g.p.TokenURL())
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "assertion rejected")
		return
	}
	resp := map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	}
	if g.refresh != nil {
		if rtok, err := g.refresh.Issue(r.Context(), subject); err == nil {
			resp["refresh_token"] = rtok
		}
	}
	writeJSON(w, http.StatusOK, resp)
```

- [ ] **Step 6: Update `main.go` wiring**

In `cmd/herald/main.go`, after `provider, err := oidc.NewProvider(...)` (and `st` is already in scope from `store.Open`), build the issuer and pass it to the grants:

```go
	refreshTTL := envDuration("HERALD_REFRESH_TTL", 0) // 0 -> issuer default (30d)
	refresh := oidc.NewRefreshIssuer(provider, st, refreshTTL)
	provider.SetTokenHandler(oidc.NewGrantMux(
		oidc.NewAgentGrant(provider, idsvc, refresh),
		oidc.NewHumanGrant(provider, idsvc, refresh),
		oidc.NewRefreshGrant(provider, idsvc, refresh), // added in Task 4
	))
```

Add the helper near the other `env*` helpers in `main.go`:

```go
func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("herald: ignoring invalid %s=%q", key, v)
	}
	return def
}
```

> `NewGrantMux` gains a third arg + `NewRefreshGrant` exists only after Task 4. To keep this task compiling on its own, temporarily wire `NewGrantMux(agent, human)` (two args) here and switch to three in Task 4. (If running tasks in order, do the two-arg form now.)

- [ ] **Step 7: Run the full build + oidc tests**

Run: `cd /Users/jacinta/Source/herald && go build ./... && go test ./internal/oidc/ ./internal/store/ -v`
Expected: build OK; tests PASS. Existing grant tests that call `NewHumanGrant`/`NewAgentGrant` with the old arity will fail to compile — update those test call sites to pass `nil` for the `refresh` arg (a nil issuer simply omits `refresh_token`, preserving their assertions).

- [ ] **Step 8: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/oidc/ cmd/herald/main.go
git commit -m "oidc: mint a rotating refresh token on the password + jwt-bearer grants"
```

---

## Task 4: oidc — the `refresh_token` grant

**Files:**
- Modify: `internal/oidc/refresh.go` (add `RefreshGrant`)
- Modify: `internal/oidc/grantmux.go`
- Modify: `internal/oidc/refresh_test.go`
- Modify: `cmd/herald/main.go` (switch to 3-arg `NewGrantMux`)

- [ ] **Step 1: Add `RefreshGrant` to `refresh.go`**

```go
// RefreshGrant implements grant_type=refresh_token: validate the presented
// refresh token, REBUILD the access-token claims from the user record (so
// scope/product/block changes take effect), rotate the refresh token, and
// return both. Rebuilding from the record means a refreshed token can never
// carry more authority than the user currently holds.
type RefreshGrant struct {
	p       *Provider
	id      IdentityResolver
	refresh *RefreshIssuer
}

func NewRefreshGrant(p *Provider, id IdentityResolver, refresh *RefreshIssuer) *RefreshGrant {
	return &RefreshGrant{p: p, id: id, refresh: refresh}
}

func (g *RefreshGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	presented := r.Form.Get("refresh_token")
	if presented == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}
	rt, err := g.refresh.validate(r.Context(), presented)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	u, err := g.id.GetUser(r.Context(), rt.UserID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	// Enforce the block cascade at refresh time (a blocked agent/human/org can't
	// renew). IsActive evaluates the agent + its responsible human + org.
	if !g.id.IsActive(r.Context(), u.ID) {
		_ = g.refresh.st.RevokeRefreshChain(r.Context(), rt.ChainID)
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	claims, err := accessClaims(r.Context(), g.id, u)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "claims failed")
		return
	}
	access, err := g.p.SignToken(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	newRefresh, err := g.refresh.rotate(r.Context(), rt)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "refresh rotation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(g.p.TTL().Seconds()),
		"refresh_token": newRefresh,
	})
}
```

> Add `"net/http"` to `refresh.go`'s imports.

Then expose `st` to `RefreshGrant`: it references `g.refresh.st` — change the `RefreshIssuer.st` field reference to be reachable. It already is (same package). No change needed.

- [ ] **Step 2: Route the grant in `grantmux.go`**

Replace `GrantMux`:

```go
type GrantMux struct {
	agent   TokenHandler
	human   TokenHandler
	refresh TokenHandler
}

func NewGrantMux(agent, human, refresh TokenHandler) *GrantMux {
	return &GrantMux{agent: agent, human: human, refresh: refresh}
}

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
	case refreshTokenGrant:
		m.refresh.ServeToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported")
	}
}
```

- [ ] **Step 3: Switch `main.go` to the 3-arg mux** (if you used the 2-arg stopgap in Task 3 Step 6, replace it with the 3-arg form shown there).

- [ ] **Step 4: Write the failing end-to-end grant test**

Append to `internal/oidc/refresh_test.go`:

```go
import (
	// add to the existing import block:
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
)

func TestRefreshGrant_EndToEnd(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := identity.New(st)
	org, _ := st.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "alice")
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, _ := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	refresh := NewRefreshIssuer(p, st, 0)
	p.SetTokenHandler(NewGrantMux(
		NewAgentGrant(p, svc, refresh),
		NewHumanGrant(p, svc, refresh),
		NewRefreshGrant(p, svc, refresh),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	post := func(form url.Values) map[string]any {
		t.Helper()
		resp, _ := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// 1. password login -> access + refresh.
	login := post(url.Values{"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"}})
	rtok, _ := login["refresh_token"].(string)
	if rtok == "" {
		t.Fatalf("login returned no refresh_token: %+v", login)
	}

	// 2. refresh -> new access + new refresh.
	r1 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if r1["access_token"] == nil || r1["refresh_token"] == nil {
		t.Fatalf("refresh failed: %+v", r1)
	}
	newR, _ := r1["refresh_token"].(string)

	// 3. the OLD refresh token is now rotated away -> rejected.
	r2 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if r2["error"] == nil {
		t.Fatalf("reused old refresh token should be rejected: %+v", r2)
	}
	// 4. replay revoked the chain -> the once-valid successor is dead too.
	r3 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {newR}})
	if r3["error"] == nil {
		t.Fatalf("successor after replay should be rejected: %+v", r3)
	}
}
```

(Add `"encoding/json"` to the import block if not present.)

- [ ] **Step 5: Run — expect PASS**

Run: `cd /Users/jacinta/Source/herald && go build ./... && go test ./internal/oidc/ -run TestRefresh -v`
Expected: build OK; `TestRefreshIssuer_*` + `TestRefreshGrant_EndToEnd` PASS.

- [ ] **Step 6: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/oidc/ cmd/herald/main.go
git commit -m "oidc: add grant_type=refresh_token (rotate + replay-revoke + claim rebuild)"
```

---

## Task 5: oidc — `POST /revoke` + discovery advertisement

**Files:**
- Modify: `internal/oidc/provider.go`
- Modify: `internal/oidc/refresh.go` (a `RevokeHandler`)
- Modify: `internal/oidc/refresh_test.go`
- Modify: `cmd/herald/main.go`

- [ ] **Step 1: Add a revoke handler type**

In `internal/oidc/refresh.go`:

```go
// RevokeHandler implements RFC 7009-style revocation for refresh tokens. Always
// 200 (idempotent, no token enumeration).
type RevokeHandler struct {
	refresh *RefreshIssuer
}

func NewRevokeHandler(refresh *RefreshIssuer) *RevokeHandler { return &RevokeHandler{refresh: refresh} }

func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	if tok := r.Form.Get("token"); tok != "" {
		h.refresh.revoke(r.Context(), tok)
	}
	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 2: Register `/revoke` + advertise in discovery**

In `internal/oidc/provider.go`:

Add a field + setter (mirroring `tokenEP`):

```go
	revokeEP http.Handler // optional; POST /revoke
```
```go
// SetRevokeHandler wires POST /revoke (refresh-token revocation).
func (p *Provider) SetRevokeHandler(h http.Handler) { p.revokeEP = h }
```

In `Handler()`, add:

```go
	mux.HandleFunc("POST /revoke", p.handleRevoke)
```

Add the handler:

```go
func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if p.revokeEP == nil {
		http.Error(w, `{"error":"revocation not configured"}`, http.StatusNotImplemented)
		return
	}
	p.revokeEP.ServeHTTP(w, r)
}
```

In `handleDiscovery`, update the map so clients can discover the new capabilities:

```go
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "password", "refresh_token"},
		"revocation_endpoint":                   base + "/revoke",
```

- [ ] **Step 3: Wire it in `main.go`**

After building `refresh` and before/with `SetTokenHandler`:

```go
	provider.SetRevokeHandler(oidc.NewRevokeHandler(refresh))
```

- [ ] **Step 4: Write the failing revoke test**

Append to `internal/oidc/refresh_test.go` (reuses the `TestRefreshGrant_EndToEnd` setup pattern — factor a small helper or inline a fresh stack):

```go
func TestRevokeEndpoint(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = st.Close() })
	svc := identity.New(st)
	org, _ := st.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "alice")
	_ = svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2")

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, _ := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	refresh := NewRefreshIssuer(p, st, 0)
	p.SetTokenHandler(NewGrantMux(NewAgentGrant(p, svc, refresh), NewHumanGrant(p, svc, refresh), NewRefreshGrant(p, svc, refresh)))
	p.SetRevokeHandler(NewRevokeHandler(refresh))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	post := func(path string, form url.Values) (int, map[string]any) {
		resp, _ := http.Post(srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	_, login := post("/token", url.Values{"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"}})
	rtok, _ := login["refresh_token"].(string)

	code, _ := post("/revoke", url.Values{"token": {rtok}})
	if code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", code)
	}
	// Revoked -> refresh now fails.
	_, after := post("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if after["error"] == nil {
		t.Fatalf("refresh after revoke should fail: %+v", after)
	}
	// Idempotent + no enumeration: revoking garbage is still 200.
	if code, _ := post("/revoke", url.Values{"token": {"garbage"}}); code != http.StatusOK {
		t.Fatalf("revoke garbage status = %d, want 200", code)
	}
}
```

- [ ] **Step 5: Run — expect PASS**

Run: `cd /Users/jacinta/Source/herald && go build ./... && go test ./internal/oidc/ -v`
Expected: all oidc tests PASS.

- [ ] **Step 6: Full suite + commit**

```bash
cd /Users/jacinta/Source/herald
go test ./... 
git add internal/oidc/ cmd/herald/main.go
git commit -m "oidc: add POST /revoke (refresh-token revocation) + advertise in discovery"
```

Expected: `go test ./...` all green.

---

## Task 6: interchange — `/herald/revoke` tokenless passthrough

The herald composite edge already passes the OIDC bootstrap (discovery, jwks, `/token`) through **unauthenticated**, and routes `/api/orgs*`+`/api/humans/*` to the gRPC AdminService. `/revoke` is a new bootstrap route and must also be unauthenticated (its credential is the refresh token in the body, not a bearer).

**Files:**
- Modify: the interchange herald-composite handler (`interchange/cmd/interchange-gateway/main.go` — search for the herald composite + the unauthenticated OIDC path list).
- Test: the interchange herald-composite test.

- [ ] **Step 1: Locate the unauthenticated herald path set**

Run: `cd /Users/jacinta/Source/interchange && grep -rn "well-known\|/token\|heraldComposite\|passthrough\|/jwks" cmd/interchange-gateway/`
Identify the predicate that lets OIDC paths bypass bearer auth (e.g. a prefix check for `/.well-known/`, `/jwks`, `/token`).

- [ ] **Step 2: Add `/revoke` to that set**

Add `/revoke` (relative to the herald prefix) alongside `/token` in the unauthenticated-OIDC predicate. If the code matches an explicit list, extend it:

```go
// OIDC bootstrap routes are the ONLY tokenless paths through interchange —
// discovery, jwks, getting a token, refreshing/revoking one.
heraldPublic := func(p string) bool {
	return p == "/.well-known/openid-configuration" ||
		p == "/jwks" ||
		p == "/token" ||
		p == "/revoke"
}
```

(Match the exact shape already in the file — only the `/revoke` addition is new.)

- [ ] **Step 3: Test it**

Add/extend the herald-composite test asserting `POST <edge>/herald/revoke` with no bearer reaches herald (not a 401 from the gateway). Run:
`cd /Users/jacinta/Source/interchange && go test ./... -run Herald -v`
Expected: PASS — `/herald/revoke` is reachable without a bearer; a random authed route still 401s.

- [ ] **Step 4: Commit**

```bash
cd /Users/jacinta/Source/interchange
git add cmd/interchange-gateway/
git commit -m "gateway: pass /herald/revoke through unauthenticated (OIDC bootstrap route)"
```

---

## Task 7: conformance — herald refresh flow

**Files:**
- Modify: `cwb-conformance/conformance/herald/herald_test.go` (add a refresh subtest)
- Possibly: `cwb-conformance/internal/wire/*.go` (a `RefreshToken`/`Revoke` helper)

- [ ] **Step 1: Add wire helpers**

In `cwb-conformance/internal/wire`, add (mirroring `LoginHuman`):

```go
// RefreshToken exchanges a refresh token for a new {access, refresh} pair.
func RefreshToken(ctx context.Context, tokenURL, refreshToken string) (access, refresh string, err error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	resp, body, err := PostForm(ctx, tokenURL, form, nil)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode/100 != 2 {
		return "", "", fmt.Errorf("refresh: status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", err
	}
	return out.AccessToken, out.RefreshToken, nil
}

// RevokeToken revokes a refresh token (always 200).
func RevokeToken(ctx context.Context, revokeURL, refreshToken string) error {
	_, _, err := PostForm(ctx, revokeURL, url.Values{"token": {refreshToken}}, nil)
	return err
}
```

> `LoginHuman` currently returns only the access token. Extend it (or add `LoginHumanFull`) to also return the `refresh_token`, since the test needs it. Prefer a new `LoginHumanFull(ctx, tokenURL, user, pw) (access, refresh string, err error)` and keep `LoginHuman` delegating to it (returns access only) to avoid touching every caller.

- [ ] **Step 2: Add the conformance subtest**

In the herald layer test, add a subtest that uses the **fixture owner** (cwadmin — the run already has `tgt.OwnerEmail`/`OwnerPassword`) or a fixture human:

```go
t.Run("RefreshAndRevoke", func(t *testing.T) {
	ctx := context.Background()
	tokenURL := tgt.TokenURL()
	revokeURL := strings.TrimSuffix(tokenURL, "/token") + "/revoke"

	access, refresh, err := wire.LoginHumanFull(ctx, tokenURL, tgt.OwnerEmail, tgt.OwnerPassword)
	if err != nil || access == "" || refresh == "" {
		t.Fatalf("login: access/refresh missing: %v", err)
	}
	// Refresh -> a fresh pair.
	a2, r2, err := wire.RefreshToken(ctx, tokenURL, refresh)
	if err != nil || a2 == "" || r2 == "" {
		t.Fatalf("refresh: %v", err)
	}
	// Old refresh token is rotated away -> rejected.
	if _, _, err := wire.RefreshToken(ctx, tokenURL, refresh); err == nil {
		t.Fatal("reused refresh token must be rejected")
	}
	// Revoke the live one -> subsequent refresh fails.
	if err := wire.RevokeToken(ctx, revokeURL, r2); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := wire.RefreshToken(ctx, tokenURL, r2); err == nil {
		t.Fatal("refresh after revoke must fail")
	}
})
```

> `tgt.TokenURL()` already exists (used by `LoginHuman`). The revoke URL is the token URL with `/token`→`/revoke`.

- [ ] **Step 3: Build the conformance suite**

Run: `cd /Users/jacinta/Source/cwb-conformance && go build ./... && go vet ./...`
Expected: clean (the live run happens in Task 8 after deploy).

- [ ] **Step 4: Commit**

```bash
cd /Users/jacinta/Source/cwb-conformance
git add internal/wire/ conformance/herald/
git commit -m "conformance: herald refresh-token issue->refresh->rotate->revoke flow"
```

---

## Task 8: deploy to dMon + verify live

**Files:** none (ops). dMon access: `ssh dmonextreme`, `sudo kubectl`. herald checkout at `~/src/herald`.

- [ ] **Step 1: Land the herald + interchange + conformance changes**

Open PRs for herald, interchange, and cwb-conformance (separate repos), CI green, merge each (squash + delete branch).

- [ ] **Step 2: Build + import the new herald image on dMon**

```bash
ssh dmonextreme 'set -e; cd ~/src/herald && git checkout main && git pull -q
  podman build -q -f cmd/herald/Containerfile -t herald:dev .
  podman save herald:dev | sudo k3s ctr images import -'
```
(If interchange changed, repeat the build/import for `~/src/interchange` and its Containerfile.)

- [ ] **Step 3: Roll out**

```bash
ssh dmonextreme 'sudo kubectl rollout restart deploy/herald -n cwb && sudo kubectl rollout status deploy/herald -n cwb --timeout=120s'
# if interchange changed:
ssh dmonextreme 'sudo kubectl rollout restart deploy/interchange-gateway -n cwb && sudo kubectl rollout status deploy/interchange-gateway -n cwb --timeout=120s'
```

Optionally set a refresh TTL: `sudo kubectl set env deploy/herald -n cwb HERALD_REFRESH_TTL=720h` (default is already 30d).

- [ ] **Step 4: Verify with conformance**

```bash
ssh dmonextreme 'set -e; cd ~/src/cwb-conformance && git checkout main && git pull -q
  OWNER_PW=$(sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.genesis_owner_password}" | base64 -d)
  CWB_OWNER_PASSWORD="$OWNER_PW" CWB_RUN_ID="verify-refresh-$$" go run ./cmd/cwb-conform -target dmon -layers herald,all'
```
Expected: all layers GREEN, including the new `herald/RefreshAndRevoke` subtest.

- [ ] **Step 5: Manual smoke (optional)**

```bash
EDGE=http://dmonextreme.tail41686e.ts.net:8080
OWNER_PW=$(ssh dmonextreme 'sudo kubectl get secret herald-secrets -n cwb -o jsonpath="{.data.genesis_owner_password}" | base64 -d')
# login -> capture refresh_token; POST grant_type=refresh_token -> new pair; POST /herald/revoke -> refresh fails.
curl -s -X POST $EDGE/herald/token -d "grant_type=password&username=cwadmin@carriedworld.com&password=$OWNER_PW" | jq '{access:.access_token!=null, refresh:.refresh_token!=null}'
```
Expected: `{access:true, refresh:true}`.

---

## Self-review

**Spec coverage (Part A of the design):**
- "issue refresh token on both grants" → Task 3 (human + agent responses). ✔
- "store row with expiry + revocation, hashed secret, parent/chain" → Task 1 (`refresh_token` table, `chain_id`, `token_hash`, `revoked_at`). ✔ (Used `chain_id` rather than `parent_id` — simpler whole-chain revoke; the spec's `parent_id` intent (replay detection) is satisfied by chain revoke.)
- "grant_type=refresh_token with rotation; reuse-of-revoked revokes chain" → Task 4 + `validate`/`rotate` in Task 3. ✔
- "new access token re-derives claims from the user at refresh time" → Task 4 uses `accessClaims` (Task 2). ✔
- "RFC 7009-style /revoke; logout path" → Task 5. ✔
- "tokenless routes extend to /herald/revoke" → Task 6. ✔
- "HERALD_REFRESH_TTL default 720h; rotation always on; access TTL unchanged" → Task 3 Step 6 + issuer default; access TTL untouched. ✔
- "conformance: issue→refresh→use→revoke→reuse-fails" → Task 7. ✔

**Placeholder scan:** no TBD/TODO; every code step shows full code; every test step shows the assertions. ✔

**Type consistency:** `RefreshToken` fields, `RefreshStore` (3 methods), `RefreshIssuer` (`Issue`/`validate`/`rotate`/`revoke`/`persist`), `NewRefreshIssuer(p, st, ttl)`, `NewRefreshGrant(p, id, refresh)`, `NewRevokeHandler(refresh)`, `NewGrantMux(agent, human, refresh)`, `NewHumanGrant(p, id, refresh)`, `NewAgentGrant(p, id, refresh)` are used consistently across tasks. `accessClaims(ctx, IdentityResolver, store.User)` is defined in Task 2 and reused in Task 4. ✔

**Note on test churn:** Tasks 3–4 change grant constructor arity; existing `internal/oidc/*_test.go` call sites must pass the new `refresh` arg (`nil` where a refresh token isn't asserted). Flagged in Task 3 Step 7.
