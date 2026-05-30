# herald path-A — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OIDC authorization_code grant + human login to herald, so cairn-native and future reliers can use herald as their IdP for browser-based human authentication.

**Architecture:** Extend the existing herald binary with HTML login UI (cookie sessions, argon2id-hashed passwords), an OIDC client registry (admin REST), an /authorize endpoint (PKCE S256 required), and a new authz_code branch in /token. Token shape stays identical to agent tokens so heraldauth verifies both paths with one code path.

**Tech Stack:** Go 1.26, existing herald deps (zitadel/oidc, modernc.org/sqlite, go-jose/v4, casket-go), adds `golang.org/x/crypto/argon2`. No frontend build pipeline — html/template + minimal CSS only.

---

## Task 1: Human credential model (argon2id passwords) — NEX-395

**Files:**
- Create: `internal/store/schema_path_a.sql`
- Create: `internal/identity/password.go`
- Create: `internal/identity/password_test.go`
- Modify: `internal/store/sqlite.go` (apply new schema fragment + add SetPasswordHash / GetPasswordHash)
- Modify: `internal/store/store.go` (extend Store interface)
- Modify: `internal/store/store_test.go` (cover new methods)
- Modify: `internal/identity/identity.go` (SetHumanPassword, VerifyHumanPassword)
- Modify: `internal/identity/identity_test.go`
- Modify: `internal/adminapi/adminapi.go` (POST /api/humans/{id}/password)
- Modify: `internal/adminapi/adminapi_test.go`

---

- [ ] **Step 1:** Add the `golang.org/x/crypto/argon2` dependency. Run:

```
cd /Users/jacinta/Source/herald && go get golang.org/x/crypto/argon2 && go mod tidy
```

Expected output prefix: `go: downloading` or no output if already cached. Verify `go.mod` has `golang.org/x/crypto v0.22.0` promoted from indirect to direct.

- [ ] **Step 2:** Create `internal/store/schema_path_a.sql` with the path-A schema additions. Write the file with exactly this content:

```sql
-- herald path-A schema additions (NEX-395..400). Applied alongside schema.sql.
-- ALTER TABLE statements are guarded by introspection in sqlite.go since
-- SQLite doesn't support IF NOT EXISTS on columns.

CREATE TABLE IF NOT EXISTS session (
  id            TEXT PRIMARY KEY,                -- 32-byte base64url-no-pad
  human_id      TEXT NOT NULL REFERENCES user(id),
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at    TEXT NOT NULL,                   -- absolute (7d from creation)
  last_seen_at  TEXT NOT NULL DEFAULT (datetime('now')),
  csrf_token    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_human ON session(human_id);
CREATE INDEX IF NOT EXISTS idx_session_expires ON session(expires_at);

CREATE TABLE IF NOT EXISTS oidc_client (
  client_id          TEXT PRIMARY KEY,
  client_secret_hash TEXT NOT NULL,
  name               TEXT NOT NULL,
  redirect_uris      TEXT NOT NULL,              -- JSON array
  allowed_scopes     TEXT NOT NULL,              -- JSON array
  first_party        INTEGER NOT NULL DEFAULT 0, -- 0|1
  created_at         TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS authz_code (
  code            TEXT PRIMARY KEY,              -- 32-byte base64url-no-pad
  client_id       TEXT NOT NULL REFERENCES oidc_client(client_id),
  human_id        TEXT NOT NULL REFERENCES user(id),
  redirect_uri    TEXT NOT NULL,
  scope           TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  expires_at      TEXT NOT NULL,
  used_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_authz_code_expires ON authz_code(expires_at);
```

- [ ] **Step 3:** In `internal/store/sqlite.go` embed the new schema and add column-introspection guards. Replace the `//go:embed schema.sql` block and Open() body section that runs schema with:

```go
//go:embed schema.sql
var schemaSQL string

//go:embed schema_path_a.sql
var schemaPathASQL string
```

And in `Open()`, after the existing `db.Exec(schemaSQL)` call, append:

```go
	if _, err := db.Exec(schemaPathASQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: apply path-A schema: %w", err)
	}
	if err := addColumnIfMissing(db, "user", "password_hash", "TEXT"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: add password_hash: %w", err)
	}
	if err := addColumnIfMissing(db, "user", "password_updated_at", "TEXT"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: add password_updated_at: %w", err)
	}
```

Then add this helper at the bottom of `sqlite.go`:

```go
func addColumnIfMissing(db *sql.DB, table, column, typ string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + typ)
	return err
}
```

- [ ] **Step 4:** Run `go build ./...` from `/Users/jacinta/Source/herald`. Expected output: no errors, exits 0. If the build fails, fix the syntax before continuing.

- [ ] **Step 5:** Add password hash storage to the Store interface. In `internal/store/store.go`, inside the `Store` interface block, add (just before `// Close releases resources.`):

```go
	// Password (humans).
	SetPasswordHash(ctx context.Context, userID, hash string) error
	GetPasswordHash(ctx context.Context, userID string) (string, error)
```

- [ ] **Step 6:** Write the failing test for SetPasswordHash/GetPasswordHash. Append to `internal/store/store_test.go`:

```go
func TestSQLite_SetGetPasswordHash(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	u, err := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := s.GetPasswordHash(ctx, u.ID); err == nil {
		t.Fatal("expected ErrNotFound for unset password")
	}
	if err := s.SetPasswordHash(ctx, u.ID, "argon2id$dummy"); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.GetPasswordHash(ctx, u.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != "argon2id$dummy" {
		t.Fatalf("hash mismatch: %q", got)
	}
}
```

- [ ] **Step 7:** Run the test, expect failure. Run:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_SetGetPasswordHash
```

Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/store` with compile error `*store.SQLite has no field or method SetPasswordHash`.

- [ ] **Step 8:** Implement SetPasswordHash + GetPasswordHash on SQLite. Append to `internal/store/sqlite.go`:

```go
func (s *SQLite) SetPasswordHash(ctx context.Context, userID, hash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE user SET password_hash = ?, password_updated_at = datetime('now') WHERE id = ? AND kind = 'human'`,
		hash, userID)
	if err != nil {
		return fmt.Errorf("SetPasswordHash: %w", err)
	}
	return mustAffect(res)
}

func (s *SQLite) GetPasswordHash(ctx context.Context, userID string) (string, error) {
	var hash sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT password_hash FROM user WHERE id = ?`, userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("GetPasswordHash: %w", err)
	}
	if !hash.Valid || hash.String == "" {
		return "", ErrNotFound
	}
	return hash.String, nil
}
```

- [ ] **Step 9:** Run the test, expect pass:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_SetGetPasswordHash
```

Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/store`.

- [ ] **Step 10:** Commit the store layer:

```
cd /Users/jacinta/Source/herald && git add internal/store go.mod go.sum && git commit -m "feat(store): add password_hash column + session/oidc_client/authz_code tables for path-A"
```

- [ ] **Step 11:** Create the argon2id wrapper. Write `internal/identity/password.go`:

```go
package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// PasswordParams tunes argon2id cost. Defaults are reasonable for a 2026 server:
// 64 MiB memory, 3 iterations, parallelism 2. Hash length 32 bytes, salt 16.
type PasswordParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	HashLen     uint32
}

// DefaultPasswordParams is the recommended default.
var DefaultPasswordParams = PasswordParams{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
	SaltLen:     16,
	HashLen:     32,
}

// HashPassword produces a PHC-encoded argon2id hash:
// "$argon2id$v=19$m=65536,t=3,p=2$<saltB64>$<hashB64>"
func HashPassword(password string, p PasswordParams) (string, error) {
	if password == "" {
		return "", errors.New("identity: password empty")
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity.HashPassword: salt: %w", err)
	}
	h := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.HashLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h)), nil
}

// VerifyPassword checks a candidate password against an encoded hash. Returns
// nil on match, an error otherwise. Constant-time on the hash compare.
func VerifyPassword(encoded, candidate string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return errors.New("identity: malformed hash")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("identity: unsupported argon2 version")
	}
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return errors.New("identity: malformed argon2 params")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("identity: malformed salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("identity: malformed hash bytes")
	}
	got := argon2.IDKey([]byte(candidate), salt, iter, mem, par, uint32(len(want)))
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return errors.New("identity: password mismatch")
	}
	return nil
}
```

- [ ] **Step 12:** Write the failing test for HashPassword/VerifyPassword. Create `internal/identity/password_test.go`:

```go
package identity_test

import (
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
)

func fastParams() identity.PasswordParams {
	return identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
}

func TestHashVerifyRoundtrip(t *testing.T) {
	h, err := identity.HashPassword("hunter2", fastParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("encoding: %q", h)
	}
	if err := identity.VerifyPassword(h, "hunter2"); err != nil {
		t.Fatalf("verify ok: %v", err)
	}
	if err := identity.VerifyPassword(h, "wrong"); err == nil {
		t.Fatal("expected mismatch error for wrong password")
	}
}

func TestHashPassword_EmptyRejected(t *testing.T) {
	if _, err := identity.HashPassword("", fastParams()); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestVerifyPassword_MalformedRejected(t *testing.T) {
	if err := identity.VerifyPassword("not-an-argon2-hash", "x"); err == nil {
		t.Fatal("expected malformed error")
	}
}
```

- [ ] **Step 13:** Run the password tests, expect pass:

```
cd /Users/jacinta/Source/herald && go test ./internal/identity/ -run 'TestHash|TestVerify'
```

Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`.

- [ ] **Step 14:** Add identity service methods. Append to `internal/identity/identity.go`:

```go
// SetHumanPassword hashes the password with argon2id and stores it on the
// human's row. Replaces any prior password.
func (svc *Service) SetHumanPassword(ctx context.Context, humanID, password string, params PasswordParams) error {
	u, err := svc.store.GetUser(ctx, humanID)
	if err != nil {
		return fmt.Errorf("identity.SetHumanPassword: %w", err)
	}
	if u.Kind != store.KindHuman {
		return errors.New("identity.SetHumanPassword: not a human")
	}
	hash, err := HashPassword(password, params)
	if err != nil {
		return fmt.Errorf("identity.SetHumanPassword: %w", err)
	}
	return svc.store.SetPasswordHash(ctx, humanID, hash)
}

// VerifyHumanPassword checks a human's password. Returns the user on success
// or an error if the human is unknown, has no password set, or the password
// does not match. Does not enforce active/blocked — callers decide.
func (svc *Service) VerifyHumanPassword(ctx context.Context, humanID, password string) (store.User, error) {
	u, err := svc.store.GetUser(ctx, humanID)
	if err != nil {
		return store.User{}, fmt.Errorf("identity.VerifyHumanPassword: %w", err)
	}
	if u.Kind != store.KindHuman {
		return store.User{}, errors.New("identity.VerifyHumanPassword: not a human")
	}
	hash, err := svc.store.GetPasswordHash(ctx, humanID)
	if err != nil {
		return store.User{}, errors.New("identity.VerifyHumanPassword: no password set")
	}
	if err := VerifyPassword(hash, password); err != nil {
		return store.User{}, errors.New("identity.VerifyHumanPassword: password mismatch")
	}
	return u, nil
}
```

- [ ] **Step 15:** Write the failing test for SetHumanPassword + VerifyHumanPassword. Append to `internal/identity/identity_test.go`:

```go
func TestService_SetVerifyHumanPassword(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer s.Close()
	svc := identity.New(s)
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "alice")
	fast := identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2", fast); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "hunter2"); err != nil {
		t.Fatalf("verify ok: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "wrong"); err == nil {
		t.Fatal("expected mismatch")
	}
}
```

- [ ] **Step 16:** Run the identity test, expect pass:

```
cd /Users/jacinta/Source/herald && go test ./internal/identity/ -run TestService_SetVerifyHumanPassword
```

Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`.

- [ ] **Step 17:** Add admin REST endpoint. In `internal/adminapi/adminapi.go`, in the `Identity` interface block append:

```go
	SetHumanPassword(ctx context.Context, humanID, password string, params identity.PasswordParams) error
```

Add import for `"github.com/CarriedWorldUniverse/herald/internal/identity"` at the top of the file. Then in `Handler()` after the existing `POST /api/humans/{id}/token` registration add:

```go
	mux.HandleFunc("POST /api/humans/{id}/password", a.adminOnly(a.handleSetHumanPassword))
```

And add this handler:

```go
func (a *API) handleSetHumanPassword(w http.ResponseWriter, r *http.Request) {
	humanID := r.PathValue("id")
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if len(body.Password) < 8 {
		writeErr(w, http.StatusBadRequest, "password must be at least 8 chars")
		return
	}
	if err := a.id.SetHumanPassword(r.Context(), humanID, body.Password, identity.DefaultPasswordParams); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": humanID, "password_set": true})
}
```

- [ ] **Step 18:** Write the failing admin test. Append to `internal/adminapi/adminapi_test.go`:

```go
func TestAPI_SetHumanPassword(t *testing.T) {
	stack := newAPIStack(t)
	org, _ := stack.id.CreateOrg(context.Background(), "acme")
	h, _ := stack.id.CreateHuman(context.Background(), org.ID, "alice")

	body := strings.NewReader(`{"password":"hunter22"}`)
	req := httptest.NewRequest("POST", "/api/humans/"+h.ID+"/password", body)
	req.Header.Set("Authorization", "Bearer "+stack.adminToken)
	w := httptest.NewRecorder()
	stack.api.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if _, err := stack.id.VerifyHumanPassword(context.Background(), h.ID, "hunter22"); err != nil {
		t.Fatalf("verify after set: %v", err)
	}
}
```

(If `newAPIStack` and friends are not in the existing test file, reuse the pattern there — peek at the first 80 lines of `adminapi_test.go` and call its existing setup. Otherwise create a thin helper matching the existing `New(idsvc, provider, adminToken)` shape.)

- [ ] **Step 19:** Run admin test:

```
cd /Users/jacinta/Source/herald && go test ./internal/adminapi/ -run TestAPI_SetHumanPassword
```

Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`.

- [ ] **Step 20:** Run the whole suite to check nothing else broke:

```
cd /Users/jacinta/Source/herald && go test ./...
```

Expected: all packages report `ok`.

- [ ] **Step 21:** Commit Task 1:

```
cd /Users/jacinta/Source/herald && git add internal/identity internal/adminapi && git commit -m "feat(identity): argon2id password hashing + admin POST /api/humans/{id}/password"
```

---

## Task 2: Session model + login/logout UI — NEX-396

**Files:**
- Create: `internal/session/session.go`
- Create: `internal/session/session_test.go`
- Create: `internal/loginui/loginui.go`
- Create: `internal/loginui/loginui_test.go`
- Create: `internal/loginui/templates/login.html`
- Create: `internal/loginui/templates/account.html`
- Modify: `internal/store/store.go` (add Session CRUD to interface)
- Modify: `internal/store/sqlite.go` (Session methods)
- Modify: `internal/store/store_test.go`
- Modify: `cmd/herald/main.go` (mount /login, /logout, /account)

---

- [ ] **Step 1:** Extend the Store interface for sessions. In `internal/store/store.go`, add the type and methods. Above the `Store` interface block, add:

```go
// Session is a server-side login session for a human.
type Session struct {
	ID         string
	HumanID    string
	CreatedAt  string
	ExpiresAt  string
	LastSeenAt string
	CSRFToken  string
}
```

Inside the `Store` interface block, before `// Close releases resources.`, add:

```go
	// Sessions (humans).
	CreateSession(ctx context.Context, s Session) (Session, error)
	GetSession(ctx context.Context, id string) (Session, error)
	TouchSession(ctx context.Context, id string, lastSeenAt string) error
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context, now string) (int64, error)
```

- [ ] **Step 2:** Write failing session-store test. Append to `internal/store/store_test.go`:

```go
func TestSQLite_SessionCRUD(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})

	now := time.Now().UTC().Format(time.RFC3339)
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	sess := store.Session{
		ID:         "sess-1",
		HumanID:    u.ID,
		CreatedAt:  now,
		ExpiresAt:  future,
		LastSeenAt: now,
		CSRFToken:  "csrf-1",
	}
	if _, err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HumanID != u.ID || got.CSRFToken != "csrf-1" {
		t.Fatalf("mismatch: %+v", got)
	}
	if err := s.DeleteSession(ctx, "sess-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetSession(ctx, "sess-1"); err == nil {
		t.Fatal("expected not-found after delete")
	}
}
```

Make sure `"time"` is imported.

- [ ] **Step 3:** Run, expect FAIL with compile error `*store.SQLite has no field or method CreateSession`:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_SessionCRUD
```

- [ ] **Step 4:** Implement session methods. Append to `internal/store/sqlite.go`:

```go
func (s *SQLite) CreateSession(ctx context.Context, sess Session) (Session, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO session (id, human_id, created_at, expires_at, last_seen_at, csrf_token)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.HumanID, sess.CreatedAt, sess.ExpiresAt, sess.LastSeenAt, sess.CSRFToken)
	if err != nil {
		return Session{}, fmt.Errorf("CreateSession: %w", err)
	}
	return s.GetSession(ctx, sess.ID)
}

func (s *SQLite) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx,
		`SELECT id, human_id, created_at, expires_at, last_seen_at, csrf_token FROM session WHERE id = ?`, id).
		Scan(&sess.ID, &sess.HumanID, &sess.CreatedAt, &sess.ExpiresAt, &sess.LastSeenAt, &sess.CSRFToken)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("GetSession: %w", err)
	}
	return sess, nil
}

func (s *SQLite) TouchSession(ctx context.Context, id string, lastSeenAt string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE session SET last_seen_at = ? WHERE id = ?`, lastSeenAt, id)
	if err != nil {
		return fmt.Errorf("TouchSession: %w", err)
	}
	return mustAffect(res)
}

func (s *SQLite) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("DeleteSession: %w", err)
	}
	return nil
}

func (s *SQLite) DeleteExpiredSessions(ctx context.Context, now string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM session WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpiredSessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
```

- [ ] **Step 5:** Run, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_SessionCRUD
```

Expected output prefix: `ok`.

- [ ] **Step 6:** Create the session manager. Write `internal/session/session.go`:

```go
// Package session is herald's cookie-backed login session manager. It owns
// session creation, lookup with idle/absolute-timeout enforcement, CSRF tokens,
// and cookie wiring. The store owns persistence; this package owns rules.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// CookieName is the session cookie key.
const CookieName = "herald_session"

// DefaultIdleTTL is the inactivity timeout.
const DefaultIdleTTL = 24 * time.Hour

// DefaultAbsoluteTTL is the maximum session lifetime.
const DefaultAbsoluteTTL = 7 * 24 * time.Hour

// Manager wraps the store with the lifecycle rules. Safe for concurrent use.
type Manager struct {
	store       store.Store
	idleTTL     time.Duration
	absoluteTTL time.Duration
	secureCookie bool
	now         func() time.Time
}

// Config configures a Manager.
type Config struct {
	Store        store.Store
	IdleTTL      time.Duration // default DefaultIdleTTL
	AbsoluteTTL  time.Duration // default DefaultAbsoluteTTL
	SecureCookie bool          // set true behind TLS
	Now          func() time.Time
}

// NewManager builds a Manager.
func NewManager(cfg Config) *Manager {
	idle := cfg.IdleTTL
	if idle == 0 {
		idle = DefaultIdleTTL
	}
	abs := cfg.AbsoluteTTL
	if abs == 0 {
		abs = DefaultAbsoluteTTL
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &Manager{
		store: cfg.Store, idleTTL: idle, absoluteTTL: abs,
		secureCookie: cfg.SecureCookie, now: nowFn,
	}
}

// Begin creates a new session for humanID, persists it, and returns the row.
// Caller is responsible for setting the cookie via SetCookie.
func (m *Manager) Begin(ctx context.Context, humanID string) (store.Session, error) {
	id, err := randomToken()
	if err != nil {
		return store.Session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return store.Session{}, err
	}
	now := m.now().UTC()
	sess := store.Session{
		ID:         id,
		HumanID:    humanID,
		CreatedAt:  now.Format(time.RFC3339),
		ExpiresAt:  now.Add(m.absoluteTTL).Format(time.RFC3339),
		LastSeenAt: now.Format(time.RFC3339),
		CSRFToken:  csrf,
	}
	return m.store.CreateSession(ctx, sess)
}

// FromRequest reads the session cookie, fetches the row, enforces both idle
// and absolute timeouts, and refreshes LastSeenAt. Returns ErrNoSession if no
// cookie, ErrExpired if either timeout has elapsed (and the row is deleted).
func (m *Manager) FromRequest(ctx context.Context, r *http.Request) (store.Session, error) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return store.Session{}, ErrNoSession
	}
	sess, err := m.store.GetSession(ctx, c.Value)
	if err != nil {
		return store.Session{}, ErrNoSession
	}
	now := m.now().UTC()
	expires, err := time.Parse(time.RFC3339, sess.ExpiresAt)
	if err != nil || now.After(expires) {
		_ = m.store.DeleteSession(ctx, sess.ID)
		return store.Session{}, ErrExpired
	}
	lastSeen, err := time.Parse(time.RFC3339, sess.LastSeenAt)
	if err == nil && now.Sub(lastSeen) > m.idleTTL {
		_ = m.store.DeleteSession(ctx, sess.ID)
		return store.Session{}, ErrExpired
	}
	_ = m.store.TouchSession(ctx, sess.ID, now.Format(time.RFC3339))
	sess.LastSeenAt = now.Format(time.RFC3339)
	return sess, nil
}

// End deletes a session row.
func (m *Manager) End(ctx context.Context, id string) error {
	return m.store.DeleteSession(ctx, id)
}

// SetCookie writes the session cookie on the response.
func (m *Manager) SetCookie(w http.ResponseWriter, sess store.Session) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		Expires:  parseRFC3339OrZero(sess.ExpiresAt),
	})
}

// ClearCookie writes a deletion cookie on the response.
func (m *Manager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secureCookie,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// ErrNoSession means no session cookie was present or the row vanished.
var ErrNoSession = errors.New("session: none")

// ErrExpired means the session existed but is past idle or absolute TTL.
var ErrExpired = errors.New("session: expired")

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func parseRFC3339OrZero(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
```

- [ ] **Step 7:** Write session manager test. Create `internal/session/session_test.go`:

```go
package session_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestManager_BeginFromRequest(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	m := session.NewManager(session.Config{Store: s})

	sess, err := m.Begin(ctx, u.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if sess.ID == "" || sess.CSRFToken == "" {
		t.Fatal("missing id or csrf")
	}

	w := httptest.NewRecorder()
	m.SetCookie(w, sess)
	req := httptest.NewRequest("GET", "/account", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	got, err := m.FromRequest(ctx, req)
	if err != nil {
		t.Fatalf("from-request: %v", err)
	}
	if got.HumanID != u.ID {
		t.Fatalf("human id mismatch: %s vs %s", got.HumanID, u.ID)
	}
}

func TestManager_FromRequest_NoCookie(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	m := session.NewManager(session.Config{Store: s})
	req := httptest.NewRequest("GET", "/account", nil)
	if _, err := m.FromRequest(ctx, req); err != session.ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestManager_FromRequest_Expired(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	clock := time.Now()
	m := session.NewManager(session.Config{
		Store: s, IdleTTL: time.Minute, AbsoluteTTL: time.Hour,
		Now: func() time.Time { return clock },
	})
	sess, _ := m.Begin(ctx, u.ID)

	w := httptest.NewRecorder()
	m.SetCookie(w, sess)
	req := httptest.NewRequest("GET", "/account", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	clock = clock.Add(2 * time.Hour) // past absolute TTL
	if _, err := m.FromRequest(ctx, req); err != session.ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestManager_End(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	m := session.NewManager(session.Config{Store: s})
	sess, _ := m.Begin(ctx, u.ID)
	if err := m.End(ctx, sess.ID); err != nil {
		t.Fatalf("end: %v", err)
	}
	w := httptest.NewRecorder()
	m.SetCookie(w, sess)
	req := httptest.NewRequest("GET", "/account", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	if _, err := m.FromRequest(ctx, req); err != session.ErrNoSession {
		t.Fatalf("expected ErrNoSession after End, got %v", err)
	}

	// Avoid unused import warning for net/http when SameSite check is the only thing.
	_ = http.SameSiteLaxMode
}
```

- [ ] **Step 8:** Run session tests, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/session/
```

Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/session`.

- [ ] **Step 9:** Create the login UI templates. Write `internal/loginui/templates/login.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sign in — herald</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 360px; margin: 4rem auto; padding: 0 1rem; }
    h1 { font-size: 1.25rem; margin-bottom: 1rem; }
    form { display: flex; flex-direction: column; gap: 0.75rem; }
    input { padding: 0.5rem; font-size: 1rem; }
    button { padding: 0.5rem; font-size: 1rem; cursor: pointer; }
    .err { color: #b00; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <h1>Sign in to herald</h1>
  {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  <form method="POST" action="/login">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="return" value="{{.Return}}">
    <label>User ID<input type="text" name="user_id" required autofocus></label>
    <label>Password<input type="password" name="password" required></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>
```

- [ ] **Step 10:** Write `internal/loginui/templates/account.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Account — herald</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; padding: 0 1rem; }
    dl { display: grid; grid-template-columns: max-content 1fr; column-gap: 1rem; row-gap: 0.25rem; }
    form { margin-top: 1rem; }
  </style>
</head>
<body>
  <h1>Signed in</h1>
  <dl>
    <dt>User</dt><dd>{{.DisplayName}}</dd>
    <dt>ID</dt><dd>{{.UserID}}</dd>
    <dt>Org</dt><dd>{{.OrgID}}</dd>
  </dl>
  <form method="POST" action="/logout">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <button type="submit">Sign out</button>
  </form>
</body>
</html>
```

- [ ] **Step 11:** Create the login UI handler. Write `internal/loginui/loginui.go`:

```go
// Package loginui is herald's HTML login surface: GET /login (form), POST
// /login (verify + cookie), POST /logout (invalidate), GET /account (signed-in
// landing). CSRF is the synchroniser-token pattern: token in session, hidden
// form field, compared on POST.
package loginui

import (
	"context"
	"crypto/subtle"
	"embed"
	"html/template"
	"net/http"
	"net/url"

	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Identity is the slice of identity.Service loginui needs.
type Identity interface {
	VerifyHumanPassword(ctx context.Context, humanID, password string) (store.User, error)
	GetUser(ctx context.Context, id string) (store.User, error)
}

// Handler exposes /login, /logout, /account.
type Handler struct {
	id      Identity
	sess    *session.Manager
	loginT  *template.Template
	acctT   *template.Template
}

// New builds a Handler.
func New(id Identity, sess *session.Manager) (*Handler, error) {
	loginT, err := template.ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		return nil, err
	}
	acctT, err := template.ParseFS(templatesFS, "templates/account.html")
	if err != nil {
		return nil, err
	}
	return &Handler{id: id, sess: sess, loginT: loginT, acctT: acctT}, nil
}

// Mount registers routes on the given mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.getLogin)
	mux.HandleFunc("POST /login", h.postLogin)
	mux.HandleFunc("POST /logout", h.postLogout)
	mux.HandleFunc("GET /account", h.getAccount)
}

type loginPage struct {
	Error  string
	CSRF   string
	Return string
}

func (h *Handler) getLogin(w http.ResponseWriter, r *http.Request) {
	ret := r.URL.Query().Get("return")
	// Get-or-create a session shell purely for the CSRF token. We don't want
	// an authenticated session here, just a stable token. Simplest approach:
	// generate a per-render token and stuff it into a short-lived "pending"
	// cookie. For MVP, we use the session's CSRF if present, else a fresh
	// random token rendered in form + cookie (double-render protected on POST
	// by re-reading the cookie). To keep state minimal we use a separate
	// short-lived cookie "herald_login_csrf".
	csrf, err := renderCSRF(w, r)
	if err != nil {
		http.Error(w, "csrf init failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.loginT.Execute(w, loginPage{CSRF: csrf, Return: ret})
}

func (h *Handler) postLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	formCSRF := r.Form.Get("csrf")
	cookieCSRF := ""
	if c, err := r.Cookie("herald_login_csrf"); err == nil {
		cookieCSRF = c.Value
	}
	if formCSRF == "" || cookieCSRF == "" || subtle.ConstantTimeCompare([]byte(formCSRF), []byte(cookieCSRF)) != 1 {
		http.Error(w, "csrf failed", http.StatusForbidden)
		return
	}
	userID := r.Form.Get("user_id")
	password := r.Form.Get("password")
	if _, err := h.id.VerifyHumanPassword(r.Context(), userID, password); err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		csrf, _ := renderCSRF(w, r)
		_ = h.loginT.Execute(w, loginPage{Error: "invalid credentials", CSRF: csrf, Return: r.Form.Get("return")})
		return
	}
	sess, err := h.sess.Begin(r.Context(), userID)
	if err != nil {
		http.Error(w, "session create failed", http.StatusInternalServerError)
		return
	}
	h.sess.SetCookie(w, sess)
	// Clear the login-CSRF cookie now that we have a real session.
	http.SetCookie(w, &http.Cookie{Name: "herald_login_csrf", Value: "", Path: "/", MaxAge: -1})

	dest := "/account"
	if ret := r.Form.Get("return"); ret != "" {
		if u, err := url.Parse(ret); err == nil && u.Scheme == "" && u.Host == "" {
			dest = ret
		}
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

func (h *Handler) postLogout(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sess.FromRequest(r.Context(), r)
	if err == nil {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Form.Get("csrf")), []byte(sess.CSRFToken)) != 1 {
			http.Error(w, "csrf failed", http.StatusForbidden)
			return
		}
		_ = h.sess.End(r.Context(), sess.ID)
	}
	h.sess.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type accountPage struct {
	UserID      string
	DisplayName string
	OrgID       string
	CSRF        string
}

func (h *Handler) getAccount(w http.ResponseWriter, r *http.Request) {
	sess, err := h.sess.FromRequest(r.Context(), r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := h.id.GetUser(r.Context(), sess.HumanID)
	if err != nil {
		http.Error(w, "user lookup failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.acctT.Execute(w, accountPage{
		UserID: u.ID, DisplayName: u.DisplayName, OrgID: u.OrgID, CSRF: sess.CSRFToken,
	})
}

// renderCSRF mints a token, sets a short-lived cookie, and returns the value
// for embedding in the form. Used only by the unauthenticated /login GET.
func renderCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie("herald_login_csrf"); err == nil && c.Value != "" {
		return c.Value, nil
	}
	tok, err := session.NewToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "herald_login_csrf",
		Value:    tok,
		Path:     "/login",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	return tok, nil
}
```

- [ ] **Step 12:** Export `NewToken` from the session package. In `internal/session/session.go` rename `randomToken` to public `NewToken`:

Use Edit replace_all from `randomToken` to `NewToken` in `internal/session/session.go`.

- [ ] **Step 13:** Write a high-level loginui integration test. Create `internal/loginui/loginui_test.go`:

```go
package loginui_test

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/loginui"
	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *identity.Service, string) {
	t.Helper()
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	org, _ := svc.CreateOrg(context.Background(), "acme")
	h, _ := svc.CreateHuman(context.Background(), org.ID, "alice")
	fast := identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
	if err := svc.SetHumanPassword(context.Background(), h.ID, "hunter22", fast); err != nil {
		t.Fatalf("setpw: %v", err)
	}
	mgr := session.NewManager(session.Config{Store: s})
	ui, err := loginui.New(svc, mgr)
	if err != nil {
		t.Fatalf("new ui: %v", err)
	}
	mux := http.NewServeMux()
	ui.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, svc, h.ID
}

func TestLogin_HappyPath(t *testing.T) {
	srv, _, humanID := newTestServer(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	// GET /login to seed the csrf cookie.
	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	resp.Body.Close()
	srvURL, _ := url.Parse(srv.URL)
	var csrf string
	for _, c := range jar.Cookies(srvURL) {
		if c.Name == "herald_login_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("no csrf cookie set")
	}

	// POST /login.
	body := url.Values{
		"csrf":     []string{csrf},
		"user_id":  []string{humanID},
		"password": []string{"hunter22"},
	}
	resp, err = client.PostForm(srv.URL+"/login", body)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "/account" {
		t.Fatalf("redirect = %q", resp.Header.Get("Location"))
	}

	// GET /account should now render the page.
	resp, err = client.Get(srv.URL + "/account")
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("account status = %d", resp.StatusCode)
	}
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "alice") {
		t.Fatalf("account body missing user name: %s", buf[:n])
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	srv, _, humanID := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(srv.URL + "/login")
	resp.Body.Close()
	srvURL, _ := url.Parse(srv.URL)
	var csrf string
	for _, c := range jar.Cookies(srvURL) {
		if c.Name == "herald_login_csrf" {
			csrf = c.Value
		}
	}
	body := url.Values{"csrf": []string{csrf}, "user_id": []string{humanID}, "password": []string{"wrong"}}
	resp, _ = client.PostForm(srv.URL+"/login", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestLogin_CSRFMismatch(t *testing.T) {
	srv, _, humanID := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(srv.URL + "/login")
	resp.Body.Close()
	body := url.Values{"csrf": []string{"forged"}, "user_id": []string{humanID}, "password": []string{"hunter22"}}
	resp, _ = client.PostForm(srv.URL+"/login", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
```

- [ ] **Step 14:** Run loginui tests, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/loginui/ ./internal/session/
```

Expected output prefix: two `ok` lines.

- [ ] **Step 15:** Wire login UI into `cmd/herald/main.go`. In the imports add `"github.com/CarriedWorldUniverse/herald/internal/loginui"` and `"github.com/CarriedWorldUniverse/herald/internal/session"`. After the existing `api := adminapi.New(...)` line, add:

```go
	sessMgr := session.NewManager(session.Config{
		Store:        st,
		SecureCookie: false, // flip when issuer is https
	})
	loginH, err := loginui.New(idsvc, sessMgr)
	if err != nil {
		log.Fatalf("herald: loginui: %v", err)
	}
```

Then before the existing `mux.Handle("/api/", api.Handler())` line add:

```go
	loginH.Mount(mux)
```

- [ ] **Step 16:** Run full suite + build:

```
cd /Users/jacinta/Source/herald && go build ./... && go test ./...
```

Expected: no build errors and all `ok`.

- [ ] **Step 17:** Commit Task 2:

```
cd /Users/jacinta/Source/herald && git add internal/session internal/loginui internal/store cmd/herald && git commit -m "feat(loginui): session manager + /login /logout /account HTML flow"
```

---

## Task 3: OIDC client registry — NEX-397

**Files:**
- Create: `internal/oidc/clients.go`
- Create: `internal/oidc/clients_test.go`
- Modify: `internal/store/store.go` (OIDCClient type + CRUD methods)
- Modify: `internal/store/sqlite.go` (OIDCClient methods)
- Modify: `internal/store/store_test.go`
- Modify: `internal/adminapi/adminapi.go` (REST: create/list/get/update/rotate-secret/delete)
- Modify: `internal/adminapi/adminapi_test.go`

---

- [ ] **Step 1:** Extend Store with OIDCClient type. In `internal/store/store.go` add above the Store interface:

```go
// OIDCClient is a registered OIDC relier (confidential client).
type OIDCClient struct {
	ClientID         string
	ClientSecretHash string
	Name             string
	RedirectURIs     []string
	AllowedScopes    []string
	FirstParty       bool
	CreatedAt        string
	UpdatedAt        string
}
```

Inside the `Store` interface block, add:

```go
	// OIDC clients.
	CreateOIDCClient(ctx context.Context, c OIDCClient) (OIDCClient, error)
	GetOIDCClient(ctx context.Context, clientID string) (OIDCClient, error)
	ListOIDCClients(ctx context.Context) ([]OIDCClient, error)
	UpdateOIDCClient(ctx context.Context, c OIDCClient) (OIDCClient, error)
	UpdateOIDCClientSecret(ctx context.Context, clientID, secretHash string) error
	DeleteOIDCClient(ctx context.Context, clientID string) error
```

- [ ] **Step 2:** Implement client CRUD on SQLite. Append to `internal/store/sqlite.go`:

```go
func (s *SQLite) CreateOIDCClient(ctx context.Context, c OIDCClient) (OIDCClient, error) {
	uris, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	fp := 0
	if c.FirstParty {
		fp = 1
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oidc_client (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, first_party)
		VALUES (?, ?, ?, ?, ?, ?)`,
		c.ClientID, c.ClientSecretHash, c.Name, string(uris), string(scopes), fp)
	if err != nil {
		return OIDCClient{}, fmt.Errorf("CreateOIDCClient: %w", err)
	}
	return s.GetOIDCClient(ctx, c.ClientID)
}

func (s *SQLite) GetOIDCClient(ctx context.Context, clientID string) (OIDCClient, error) {
	var c OIDCClient
	var uris, scopes string
	var fp int
	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, client_secret_hash, name, redirect_uris, allowed_scopes, first_party, created_at, updated_at
		FROM oidc_client WHERE client_id = ?`, clientID).
		Scan(&c.ClientID, &c.ClientSecretHash, &c.Name, &uris, &scopes, &fp, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OIDCClient{}, ErrNotFound
	}
	if err != nil {
		return OIDCClient{}, fmt.Errorf("GetOIDCClient: %w", err)
	}
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	_ = json.Unmarshal([]byte(scopes), &c.AllowedScopes)
	c.FirstParty = fp != 0
	return c, nil
}

func (s *SQLite) ListOIDCClients(ctx context.Context) ([]OIDCClient, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT client_id, client_secret_hash, name, redirect_uris, allowed_scopes, first_party, created_at, updated_at
		FROM oidc_client ORDER BY client_id`)
	if err != nil {
		return nil, fmt.Errorf("ListOIDCClients: %w", err)
	}
	defer rows.Close()
	var out []OIDCClient
	for rows.Next() {
		var c OIDCClient
		var uris, scopes string
		var fp int
		if err := rows.Scan(&c.ClientID, &c.ClientSecretHash, &c.Name, &uris, &scopes, &fp, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
		_ = json.Unmarshal([]byte(scopes), &c.AllowedScopes)
		c.FirstParty = fp != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateOIDCClient(ctx context.Context, c OIDCClient) (OIDCClient, error) {
	uris, _ := json.Marshal(c.RedirectURIs)
	scopes, _ := json.Marshal(c.AllowedScopes)
	fp := 0
	if c.FirstParty {
		fp = 1
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE oidc_client SET name = ?, redirect_uris = ?, allowed_scopes = ?, first_party = ?, updated_at = datetime('now')
		WHERE client_id = ?`,
		c.Name, string(uris), string(scopes), fp, c.ClientID)
	if err != nil {
		return OIDCClient{}, fmt.Errorf("UpdateOIDCClient: %w", err)
	}
	if err := mustAffect(res); err != nil {
		return OIDCClient{}, err
	}
	return s.GetOIDCClient(ctx, c.ClientID)
}

func (s *SQLite) UpdateOIDCClientSecret(ctx context.Context, clientID, secretHash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE oidc_client SET client_secret_hash = ?, updated_at = datetime('now') WHERE client_id = ?`,
		secretHash, clientID)
	if err != nil {
		return fmt.Errorf("UpdateOIDCClientSecret: %w", err)
	}
	return mustAffect(res)
}

func (s *SQLite) DeleteOIDCClient(ctx context.Context, clientID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM oidc_client WHERE client_id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("DeleteOIDCClient: %w", err)
	}
	return nil
}
```

Make sure `"encoding/json"` is imported in `sqlite.go`.

- [ ] **Step 3:** Write the failing client-store test. Append to `internal/store/store_test.go`:

```go
func TestSQLite_OIDCClientCRUD(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	c, err := s.CreateOIDCClient(ctx, store.OIDCClient{
		ClientID:         "cairn-native",
		ClientSecretHash: "argon2id$x",
		Name:             "cairn native",
		RedirectURIs:     []string{"https://cairn/oauth/callback"},
		AllowedScopes:    []string{"repo:read", "repo:write"},
		FirstParty:       true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ClientID != "cairn-native" || !c.FirstParty {
		t.Fatalf("create round-trip: %+v", c)
	}
	got, err := s.GetOIDCClient(ctx, "cairn-native")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://cairn/oauth/callback" {
		t.Fatalf("redirect uris: %+v", got.RedirectURIs)
	}
	if err := s.UpdateOIDCClientSecret(ctx, "cairn-native", "argon2id$y"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got2, _ := s.GetOIDCClient(ctx, "cairn-native")
	if got2.ClientSecretHash != "argon2id$y" {
		t.Fatalf("rotate not applied: %q", got2.ClientSecretHash)
	}
	if err := s.DeleteOIDCClient(ctx, "cairn-native"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetOIDCClient(ctx, "cairn-native"); err == nil {
		t.Fatal("expected not-found after delete")
	}
}
```

- [ ] **Step 4:** Run, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_OIDCClientCRUD
```

Expected output prefix: `ok`.

- [ ] **Step 5:** Create the client-registry service that owns secret hashing + first-party rules. Write `internal/oidc/clients.go`:

```go
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ClientRegistry owns the OIDC client lifecycle: create with generated secret,
// secret rotation, lookup with secret verification. The store is dumb CRUD;
// hashing rules live here.
type ClientRegistry struct {
	store  store.Store
	params identity.PasswordParams
}

// NewClientRegistry builds a registry using the given password params for
// secret hashing (we reuse argon2id from identity to avoid a second primitive).
func NewClientRegistry(s store.Store, p identity.PasswordParams) *ClientRegistry {
	return &ClientRegistry{store: s, params: p}
}

// ClientCreate is the input to Create.
type ClientCreate struct {
	ClientID      string
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	FirstParty    bool
}

// CreateResult bundles the persisted client + the cleartext secret. The
// cleartext is returned exactly once at create time and never again.
type CreateResult struct {
	Client       store.OIDCClient
	ClientSecret string
}

// Create generates a fresh client secret, hashes it, persists the client.
func (r *ClientRegistry) Create(ctx context.Context, in ClientCreate) (CreateResult, error) {
	if in.ClientID == "" {
		return CreateResult{}, errors.New("oidc: client_id required")
	}
	if in.Name == "" {
		return CreateResult{}, errors.New("oidc: name required")
	}
	if len(in.RedirectURIs) == 0 {
		return CreateResult{}, errors.New("oidc: at least one redirect_uri required")
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return CreateResult{}, err
		}
	}
	secret, err := newSecret()
	if err != nil {
		return CreateResult{}, err
	}
	hash, err := identity.HashPassword(secret, r.params)
	if err != nil {
		return CreateResult{}, err
	}
	c, err := r.store.CreateOIDCClient(ctx, store.OIDCClient{
		ClientID:         in.ClientID,
		ClientSecretHash: hash,
		Name:             in.Name,
		RedirectURIs:     in.RedirectURIs,
		AllowedScopes:    in.AllowedScopes,
		FirstParty:       in.FirstParty,
	})
	if err != nil {
		return CreateResult{}, err
	}
	return CreateResult{Client: c, ClientSecret: secret}, nil
}

// Get returns a client by id.
func (r *ClientRegistry) Get(ctx context.Context, clientID string) (store.OIDCClient, error) {
	return r.store.GetOIDCClient(ctx, clientID)
}

// List returns all registered clients (secret hashes included; callers must
// not echo them to admin REST responses).
func (r *ClientRegistry) List(ctx context.Context) ([]store.OIDCClient, error) {
	return r.store.ListOIDCClients(ctx)
}

// Update updates the non-secret fields of a client.
func (r *ClientRegistry) Update(ctx context.Context, in ClientCreate) (store.OIDCClient, error) {
	if in.ClientID == "" {
		return store.OIDCClient{}, errors.New("oidc: client_id required")
	}
	existing, err := r.store.GetOIDCClient(ctx, in.ClientID)
	if err != nil {
		return store.OIDCClient{}, err
	}
	for _, u := range in.RedirectURIs {
		if err := validateRedirectURI(u); err != nil {
			return store.OIDCClient{}, err
		}
	}
	existing.Name = in.Name
	existing.RedirectURIs = in.RedirectURIs
	existing.AllowedScopes = in.AllowedScopes
	existing.FirstParty = in.FirstParty
	return r.store.UpdateOIDCClient(ctx, existing)
}

// RotateSecret generates a new secret, hashes it, persists the hash, returns
// the cleartext (one-time return).
func (r *ClientRegistry) RotateSecret(ctx context.Context, clientID string) (string, error) {
	if _, err := r.store.GetOIDCClient(ctx, clientID); err != nil {
		return "", err
	}
	secret, err := newSecret()
	if err != nil {
		return "", err
	}
	hash, err := identity.HashPassword(secret, r.params)
	if err != nil {
		return "", err
	}
	if err := r.store.UpdateOIDCClientSecret(ctx, clientID, hash); err != nil {
		return "", err
	}
	return secret, nil
}

// Delete removes a client.
func (r *ClientRegistry) Delete(ctx context.Context, clientID string) error {
	return r.store.DeleteOIDCClient(ctx, clientID)
}

// VerifySecret returns nil if the candidate matches the stored hash for clientID.
func (r *ClientRegistry) VerifySecret(ctx context.Context, clientID, candidate string) (store.OIDCClient, error) {
	c, err := r.store.GetOIDCClient(ctx, clientID)
	if err != nil {
		return store.OIDCClient{}, err
	}
	if err := identity.VerifyPassword(c.ClientSecretHash, candidate); err != nil {
		return store.OIDCClient{}, errors.New("oidc: client secret mismatch")
	}
	return c, nil
}

// validateRedirectURI rejects junk URIs. Exact-match is enforced elsewhere; this
// is the shape check (scheme + host + no fragment).
func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("oidc: invalid redirect_uri %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("oidc: redirect_uri must be http or https: %q", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("oidc: redirect_uri missing host: %q", raw)
	}
	if u.Fragment != "" {
		return fmt.Errorf("oidc: redirect_uri must not contain fragment: %q", raw)
	}
	return nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

- [ ] **Step 6:** Write the registry test. Create `internal/oidc/clients_test.go`:

```go
package oidc_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	heraldoidc "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func fastParams() identity.PasswordParams {
	return identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
}

func TestClientRegistry_CreateAndVerify(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	r := heraldoidc.NewClientRegistry(s, fastParams())
	res, err := r.Create(ctx, heraldoidc.ClientCreate{
		ClientID:      "cairn-native",
		Name:          "cairn native",
		RedirectURIs:  []string{"https://cairn/oauth/callback"},
		AllowedScopes: []string{"repo:read"},
		FirstParty:    true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.ClientSecret == "" {
		t.Fatal("missing cleartext secret")
	}
	if _, err := r.VerifySecret(ctx, "cairn-native", res.ClientSecret); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := r.VerifySecret(ctx, "cairn-native", "wrong"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestClientRegistry_RotateSecret(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	r := heraldoidc.NewClientRegistry(s, fastParams())
	res, _ := r.Create(ctx, heraldoidc.ClientCreate{
		ClientID: "x", Name: "x",
		RedirectURIs: []string{"https://x/cb"},
	})
	newSecret, err := r.RotateSecret(ctx, "x")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if newSecret == res.ClientSecret {
		t.Fatal("rotate produced same secret")
	}
	if _, err := r.VerifySecret(ctx, "x", res.ClientSecret); err == nil {
		t.Fatal("old secret should not verify after rotate")
	}
	if _, err := r.VerifySecret(ctx, "x", newSecret); err != nil {
		t.Fatalf("new secret verify: %v", err)
	}
}

func TestClientRegistry_RejectsBadRedirect(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	r := heraldoidc.NewClientRegistry(s, fastParams())
	_, err := r.Create(ctx, heraldoidc.ClientCreate{
		ClientID: "x", Name: "x",
		RedirectURIs: []string{"ftp://x/cb"},
	})
	if err == nil {
		t.Fatal("expected reject of ftp scheme")
	}
}
```

- [ ] **Step 7:** Run client tests, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -run TestClientRegistry
```

Expected output prefix: `ok`.

- [ ] **Step 8:** Add admin REST. In `internal/adminapi/adminapi.go`, add a new field `clients *oidc.ClientRegistry` on `API`. Update `New` signature to accept it:

```go
func New(id Identity, tokens TokenIssuer, clients *oidc.ClientRegistry, adminToken string) *API {
	return &API{id: id, tokens: tokens, clients: clients, adminToken: adminToken}
}
```

Add import for `"github.com/CarriedWorldUniverse/herald/internal/oidc"`. In the `Handler()` method add:

```go
	mux.HandleFunc("POST /api/oidc/clients", a.adminOnly(a.handleCreateOIDCClient))
	mux.HandleFunc("GET /api/oidc/clients", a.adminOnly(a.handleListOIDCClients))
	mux.HandleFunc("GET /api/oidc/clients/{id}", a.adminOnly(a.handleGetOIDCClient))
	mux.HandleFunc("PUT /api/oidc/clients/{id}", a.adminOnly(a.handleUpdateOIDCClient))
	mux.HandleFunc("POST /api/oidc/clients/{id}/rotate-secret", a.adminOnly(a.handleRotateOIDCClientSecret))
	mux.HandleFunc("DELETE /api/oidc/clients/{id}", a.adminOnly(a.handleDeleteOIDCClient))
```

And the handlers (append to file):

```go
type oidcClientBody struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	FirstParty    bool     `json:"first_party"`
}

func clientToWire(c store.OIDCClient) map[string]any {
	return map[string]any{
		"client_id":      c.ClientID,
		"name":           c.Name,
		"redirect_uris":  c.RedirectURIs,
		"allowed_scopes": c.AllowedScopes,
		"first_party":    c.FirstParty,
		"created_at":     c.CreatedAt,
		"updated_at":     c.UpdatedAt,
	}
}

func (a *API) handleCreateOIDCClient(w http.ResponseWriter, r *http.Request) {
	var body oidcClientBody
	if !decode(w, r, &body) {
		return
	}
	res, err := a.clients.Create(r.Context(), oidc.ClientCreate{
		ClientID: body.ClientID, Name: body.Name,
		RedirectURIs: body.RedirectURIs, AllowedScopes: body.AllowedScopes,
		FirstParty: body.FirstParty,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := clientToWire(res.Client)
	out["client_secret"] = res.ClientSecret // one-time return
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleListOIDCClients(w http.ResponseWriter, r *http.Request) {
	cs, err := a.clients.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	wire := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		wire = append(wire, clientToWire(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": wire})
}

func (a *API) handleGetOIDCClient(w http.ResponseWriter, r *http.Request) {
	c, err := a.clients.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clientToWire(c))
}

func (a *API) handleUpdateOIDCClient(w http.ResponseWriter, r *http.Request) {
	var body oidcClientBody
	if !decode(w, r, &body) {
		return
	}
	body.ClientID = r.PathValue("id")
	c, err := a.clients.Update(r.Context(), oidc.ClientCreate{
		ClientID: body.ClientID, Name: body.Name,
		RedirectURIs: body.RedirectURIs, AllowedScopes: body.AllowedScopes,
		FirstParty: body.FirstParty,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, clientToWire(c))
}

func (a *API) handleRotateOIDCClientSecret(w http.ResponseWriter, r *http.Request) {
	secret, err := a.clients.RotateSecret(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client_id": r.PathValue("id"), "client_secret": secret})
}

func (a *API) handleDeleteOIDCClient(w http.ResponseWriter, r *http.Request) {
	if err := a.clients.Delete(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 9:** Update `cmd/herald/main.go` to construct and pass the client registry. After the existing `idsvc := identity.New(st)` line add:

```go
	clients := oidc.NewClientRegistry(st, identity.DefaultPasswordParams)
```

And update the `adminapi.New` call:

```go
	api := adminapi.New(idsvc, provider, clients, adminToken)
```

Add `"github.com/CarriedWorldUniverse/herald/internal/identity"` to the imports if not present.

- [ ] **Step 10:** Update existing adminapi tests that call `adminapi.New(...)` to pass a registry. In `internal/adminapi/adminapi_test.go`, find every call site of `adminapi.New(`, e.g. `adminapi.New(svc, prov, "tok")` and update to `adminapi.New(svc, prov, oidc.NewClientRegistry(s, fastParams()), "tok")`. If the test file has a helper like `newAPIStack`, update there. Add the import block to include `"github.com/CarriedWorldUniverse/herald/internal/oidc"` and ensure `fastParams()` is defined in this test file or referenced from another test file in the same package.

- [ ] **Step 11:** Write a new admin REST test for client CRUD. Append to `internal/adminapi/adminapi_test.go`:

```go
func TestAPI_OIDCClient_CRUD(t *testing.T) {
	stack := newAPIStack(t)
	create := `{"client_id":"cairn-native","name":"cairn","redirect_uris":["https://cairn/cb"],"allowed_scopes":["repo:read"],"first_party":true}`
	req := httptest.NewRequest("POST", "/api/oidc/clients", strings.NewReader(create))
	req.Header.Set("Authorization", "Bearer "+stack.adminToken)
	w := httptest.NewRecorder()
	stack.api.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("create status = %d body=%s", w.Code, w.Body.String())
	}
	var createResp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if createResp["client_secret"] == "" || createResp["client_secret"] == nil {
		t.Fatal("client_secret missing in create response")
	}

	// GET single
	req = httptest.NewRequest("GET", "/api/oidc/clients/cairn-native", nil)
	req.Header.Set("Authorization", "Bearer "+stack.adminToken)
	w = httptest.NewRecorder()
	stack.api.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("get status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "client_secret") {
		t.Fatal("GET should not expose client_secret")
	}

	// Rotate
	req = httptest.NewRequest("POST", "/api/oidc/clients/cairn-native/rotate-secret", nil)
	req.Header.Set("Authorization", "Bearer "+stack.adminToken)
	w = httptest.NewRecorder()
	stack.api.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("rotate status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "client_secret") {
		t.Fatal("rotate should return new client_secret")
	}

	// Delete
	req = httptest.NewRequest("DELETE", "/api/oidc/clients/cairn-native", nil)
	req.Header.Set("Authorization", "Bearer "+stack.adminToken)
	w = httptest.NewRecorder()
	stack.api.Handler().ServeHTTP(w, req)
	if w.Code != 204 {
		t.Fatalf("delete status = %d", w.Code)
	}
}
```

(Use the existing `newAPIStack` helper in the test file; if it doesn't exist, add one that mirrors the existing setup pattern: open `:memory:` store, build identity service, provider, registry, and adminapi.)

- [ ] **Step 12:** Run all tests:

```
cd /Users/jacinta/Source/herald && go test ./...
```

Expected: all `ok`.

- [ ] **Step 13:** Commit Task 3:

```
cd /Users/jacinta/Source/herald && git add internal/store internal/oidc internal/adminapi cmd/herald && git commit -m "feat(oidc): client registry with hashed secrets + admin CRUD REST"
```

---

## Task 4: /authorize endpoint + PKCE — NEX-398

**Files:**
- Create: `internal/oidc/authz.go`
- Create: `internal/oidc/authz_test.go`
- Modify: `internal/store/store.go` (AuthzCode type + CRUD)
- Modify: `internal/store/sqlite.go` (AuthzCode methods)
- Modify: `internal/store/store_test.go`
- Modify: `internal/oidc/provider.go` (discovery doc updates: response_types, grant_types, code_challenge_methods, token_endpoint_auth_methods)
- Modify: `cmd/herald/main.go` (mount /authorize)

---

- [ ] **Step 1:** Extend Store for authz_codes. In `internal/store/store.go` add above the Store interface:

```go
// AuthzCode is a single-use OAuth authorization code.
type AuthzCode struct {
	Code           string
	ClientID       string
	HumanID        string
	RedirectURI    string
	Scope          string
	CodeChallenge  string
	ExpiresAt      string
	UsedAt         string // empty = unused
}
```

Inside the `Store` interface block, add:

```go
	// Authz codes (path-A authorization_code grant).
	CreateAuthzCode(ctx context.Context, c AuthzCode) error
	ConsumeAuthzCode(ctx context.Context, code, now string) (AuthzCode, error)
	DeleteExpiredAuthzCodes(ctx context.Context, now string) (int64, error)
```

- [ ] **Step 2:** Implement on SQLite. Append to `internal/store/sqlite.go`:

```go
func (s *SQLite) CreateAuthzCode(ctx context.Context, c AuthzCode) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO authz_code (code, client_id, human_id, redirect_uri, scope, code_challenge, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.Code, c.ClientID, c.HumanID, c.RedirectURI, c.Scope, c.CodeChallenge, c.ExpiresAt)
	if err != nil {
		return fmt.Errorf("CreateAuthzCode: %w", err)
	}
	return nil
}

// ConsumeAuthzCode atomically marks the code used and returns its fields, or
// ErrNotFound if it was already used / expired / never existed.
func (s *SQLite) ConsumeAuthzCode(ctx context.Context, code, now string) (AuthzCode, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuthzCode{}, fmt.Errorf("ConsumeAuthzCode: begin: %w", err)
	}
	defer tx.Rollback()
	var c AuthzCode
	err = tx.QueryRowContext(ctx, `
		SELECT code, client_id, human_id, redirect_uri, scope, code_challenge, expires_at, COALESCE(used_at, '')
		FROM authz_code WHERE code = ?`, code).
		Scan(&c.Code, &c.ClientID, &c.HumanID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.ExpiresAt, &c.UsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthzCode{}, ErrNotFound
	}
	if err != nil {
		return AuthzCode{}, fmt.Errorf("ConsumeAuthzCode: select: %w", err)
	}
	if c.UsedAt != "" {
		return AuthzCode{}, ErrNotFound
	}
	if c.ExpiresAt < now {
		return AuthzCode{}, ErrNotFound
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE authz_code SET used_at = ? WHERE code = ? AND used_at IS NULL`, now, code)
	if err != nil {
		return AuthzCode{}, fmt.Errorf("ConsumeAuthzCode: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return AuthzCode{}, ErrNotFound
	}
	if err := tx.Commit(); err != nil {
		return AuthzCode{}, fmt.Errorf("ConsumeAuthzCode: commit: %w", err)
	}
	c.UsedAt = now
	return c, nil
}

func (s *SQLite) DeleteExpiredAuthzCodes(ctx context.Context, now string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM authz_code WHERE expires_at < ?`, now)
	if err != nil {
		return 0, fmt.Errorf("DeleteExpiredAuthzCodes: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
```

- [ ] **Step 3:** Write failing store test. Append to `internal/store/store_test.go`:

```go
func TestSQLite_AuthzCode_ConsumeIsAtomic(t *testing.T) {
	ctx := context.Background()
	s, _ := store.Open(":memory:")
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})
	_, _ = s.CreateOIDCClient(ctx, store.OIDCClient{
		ClientID: "x", ClientSecretHash: "h", Name: "x",
		RedirectURIs: []string{"https://x/cb"}, AllowedScopes: []string{"repo:read"},
	})
	future := time.Now().UTC().Add(time.Minute).Format(time.RFC3339)
	if err := s.CreateAuthzCode(ctx, store.AuthzCode{
		Code: "c1", ClientID: "x", HumanID: u.ID,
		RedirectURI: "https://x/cb", Scope: "repo:read",
		CodeChallenge: "abc", ExpiresAt: future,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	got, err := s.ConsumeAuthzCode(ctx, "c1", now)
	if err != nil {
		t.Fatalf("consume 1: %v", err)
	}
	if got.HumanID != u.ID {
		t.Fatalf("human id: %s", got.HumanID)
	}
	if _, err := s.ConsumeAuthzCode(ctx, "c1", now); err == nil {
		t.Fatal("second consume should fail (single-use)")
	}
}
```

- [ ] **Step 4:** Run test, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestSQLite_AuthzCode_ConsumeIsAtomic
```

Expected output prefix: `ok`.

- [ ] **Step 5:** Update the OIDC discovery doc. In `internal/oidc/provider.go`, replace the `handleDiscovery` body's map literal with:

```go
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"jwks_uri":                              base + "/jwks",
		"token_endpoint":                        base + "/token",
		"authorization_endpoint":                base + "/authorize",
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "authorization_code"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "client_secret_basic", "client_secret_post"},
		"response_types_supported":              []string{"token", "code"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
```

- [ ] **Step 6:** Create the /authorize handler. Write `internal/oidc/authz.go`:

```go
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// AuthzCodeTTL is the lifetime of an authorization code (RFC 6749 recommends short).
const AuthzCodeTTL = 60 * time.Second

// AuthzHandler implements GET /authorize. It checks the herald session cookie,
// redirects to /login if absent, validates the OIDC request, persists a
// single-use authorization code, and 302s back to the relier's redirect_uri.
type AuthzHandler struct {
	clients *ClientRegistry
	sess    *session.Manager
	store   store.Store
	now     func() time.Time
}

// NewAuthzHandler builds an /authorize handler.
func NewAuthzHandler(clients *ClientRegistry, sess *session.Manager, s store.Store) *AuthzHandler {
	return &AuthzHandler{
		clients: clients, sess: sess, store: s,
		now: time.Now,
	}
}

// Mount registers GET /authorize on the given mux.
func (h *AuthzHandler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /authorize", h.handle)
}

func (h *AuthzHandler) handle(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")

	// 1. Validate client + redirect_uri BEFORE redirecting anywhere else, so
	//    bogus clients can't induce open redirects via state.
	if clientID == "" || redirectURI == "" {
		http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
		return
	}
	c, err := h.clients.Get(r.Context(), clientID)
	if err != nil {
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	if !exactMatch(c.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered", http.StatusBadRequest)
		return
	}

	// 2. Remaining validation: errors past this point return to the relier
	//    via redirect with ?error=… so the client can surface them.
	if responseType != "code" {
		redirectErr(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if challengeMethod != "S256" {
		redirectErr(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256")
		return
	}
	if challenge == "" {
		redirectErr(w, r, redirectURI, state, "invalid_request", "code_challenge required")
		return
	}
	if !subsetScope(c.AllowedScopes, scope) {
		redirectErr(w, r, redirectURI, state, "invalid_scope", "requested scope not allowed for client")
		return
	}

	// 3. Auto-consent only for first-party clients.
	if !c.FirstParty {
		redirectErr(w, r, redirectURI, state, "access_denied", "consent UI not available; first-party clients only for MVP")
		return
	}

	// 4. Check the session; if none, bounce to /login with return URL.
	sess, err := h.sess.FromRequest(r.Context(), r)
	if err != nil {
		ret := r.URL.RequestURI()
		http.Redirect(w, r, "/login?return="+url.QueryEscape(ret), http.StatusSeeOther)
		return
	}

	// 5. Mint and persist the code.
	code, err := newAuthzCode()
	if err != nil {
		redirectErr(w, r, redirectURI, state, "server_error", "code mint failed")
		return
	}
	now := h.now().UTC()
	if err := h.store.CreateAuthzCode(r.Context(), store.AuthzCode{
		Code:          code,
		ClientID:      clientID,
		HumanID:       sess.HumanID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		CodeChallenge: challenge,
		ExpiresAt:     now.Add(AuthzCodeTTL).Format(time.RFC3339),
	}); err != nil {
		redirectErr(w, r, redirectURI, state, "server_error", "code persist failed")
		return
	}

	// 6. 302 back to the relier with code + state.
	u, _ := url.Parse(redirectURI)
	qv := u.Query()
	qv.Set("code", code)
	if state != "" {
		qv.Set("state", state)
	}
	u.RawQuery = qv.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func exactMatch(list []string, want string) bool {
	for _, u := range list {
		if u == want {
			return true
		}
	}
	return false
}

func subsetScope(allowed []string, requested string) bool {
	if requested == "" {
		return true
	}
	for _, s := range strings.Fields(requested) {
		ok := false
		for _, a := range allowed {
			if a == s {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func redirectErr(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, fmt.Sprintf("%s: %s", code, desc), http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func newAuthzCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ContextRoot exists to silence unused import warnings during the early build.
var _ = context.Background
var _ = errors.New
```

- [ ] **Step 7:** Write the authz handler test. Create `internal/oidc/authz_test.go`:

```go
package oidc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/loginui"
	heraldoidc "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

type authzStack struct {
	srv     *httptest.Server
	humanID string
	clientID string
	secret  string
}

func newAuthzStack(t *testing.T) authzStack {
	t.Helper()
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	org, _ := svc.CreateOrg(context.Background(), "acme")
	h, _ := svc.CreateHuman(context.Background(), org.ID, "alice")
	fast := identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
	_ = svc.SetHumanPassword(context.Background(), h.ID, "hunter22", fast)
	clients := heraldoidc.NewClientRegistry(s, fast)
	res, err := clients.Create(context.Background(), heraldoidc.ClientCreate{
		ClientID: "cairn-native", Name: "cairn",
		RedirectURIs:  []string{"https://relier.example/cb"},
		AllowedScopes: []string{"repo:read", "repo:write"},
		FirstParty:    true,
	})
	if err != nil {
		t.Fatalf("client create: %v", err)
	}
	mgr := session.NewManager(session.Config{Store: s})
	authz := heraldoidc.NewAuthzHandler(clients, mgr, s)
	ui, _ := loginui.New(svc, mgr)

	mux := http.NewServeMux()
	ui.Mount(mux)
	authz.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return authzStack{srv: srv, humanID: h.ID, clientID: "cairn-native", secret: res.ClientSecret}
}

func pkcePair() (verifier, challenge string) {
	verifier = "the-quick-brown-fox-jumps-over-the-lazy-dog-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func loginClient(t *testing.T, srvURL, humanID string) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(srvURL + "/login")
	resp.Body.Close()
	u, _ := url.Parse(srvURL)
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "herald_login_csrf" {
			csrf = c.Value
		}
	}
	body := url.Values{"csrf": []string{csrf}, "user_id": []string{humanID}, "password": []string{"hunter22"}}
	resp, _ = client.PostForm(srvURL+"/login", body)
	resp.Body.Close()
	return client
}

func TestAuthorize_HappyPath(t *testing.T) {
	st := newAuthzStack(t)
	client := loginClient(t, st.srv.URL, st.humanID)

	_, challenge := pkcePair()
	q := url.Values{
		"client_id":             []string{st.clientID},
		"redirect_uri":          []string{"https://relier.example/cb"},
		"response_type":         []string{"code"},
		"scope":                 []string{"repo:read"},
		"state":                 []string{"xyz"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	resp, err := client.Get(st.srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://relier.example/cb?") {
		t.Fatalf("location = %q", loc)
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Fatalf("missing code in %q", loc)
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed: %q", loc)
	}
}

func TestAuthorize_NoSession_RedirectsToLogin(t *testing.T) {
	st := newAuthzStack(t)
	_, challenge := pkcePair()
	q := url.Values{
		"client_id":             []string{st.clientID},
		"redirect_uri":          []string{"https://relier.example/cb"},
		"response_type":         []string{"code"},
		"scope":                 []string{"repo:read"},
		"state":                 []string{"xyz"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(st.srv.URL + "/authorize?" + q.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login?return=") {
		t.Fatalf("expected /login?return=…, got %q", resp.Header.Get("Location"))
	}
}

func TestAuthorize_UnknownClient(t *testing.T) {
	st := newAuthzStack(t)
	client := loginClient(t, st.srv.URL, st.humanID)
	resp, _ := client.Get(st.srv.URL + "/authorize?client_id=nope&redirect_uri=https://x/cb")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestAuthorize_BadRedirect(t *testing.T) {
	st := newAuthzStack(t)
	client := loginClient(t, st.srv.URL, st.humanID)
	resp, _ := client.Get(st.srv.URL + "/authorize?client_id=" + st.clientID + "&redirect_uri=https://evil/cb")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.StatusCode, "")
	}
}

func TestAuthorize_BadScope(t *testing.T) {
	st := newAuthzStack(t)
	client := loginClient(t, st.srv.URL, st.humanID)
	_, challenge := pkcePair()
	q := url.Values{
		"client_id":             []string{st.clientID},
		"redirect_uri":          []string{"https://relier.example/cb"},
		"response_type":         []string{"code"},
		"scope":                 []string{"admin:everything"},
		"state":                 []string{"s"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	resp, _ := client.Get(st.srv.URL + "/authorize?" + q.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	if u.Query().Get("error") != "invalid_scope" {
		t.Fatalf("error = %q", u.Query().Get("error"))
	}
}
```

- [ ] **Step 8:** Run authz tests, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -run TestAuthorize
```

Expected output prefix: `ok`.

- [ ] **Step 9:** Mount /authorize in `cmd/herald/main.go`. After the `loginH.Mount(mux)` line add:

```go
	authzH := oidc.NewAuthzHandler(clients, sessMgr, st)
	authzH.Mount(mux)
```

- [ ] **Step 10:** Verify discovery doc updates with a test. Append to `internal/oidc/oidc_test.go`:

```go
func TestProvider_DiscoveryPathA(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	defer resp.Body.Close()
	var d map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&d)
	rts, _ := d["response_types_supported"].([]any)
	foundCode := false
	for _, v := range rts {
		if s, _ := v.(string); s == "code" {
			foundCode = true
		}
	}
	if !foundCode {
		t.Fatalf("response_types_supported missing code: %+v", rts)
	}
	gts, _ := d["grant_types_supported"].([]any)
	foundAC := false
	for _, v := range gts {
		if s, _ := v.(string); s == "authorization_code" {
			foundAC = true
		}
	}
	if !foundAC {
		t.Fatalf("grant_types_supported missing authorization_code: %+v", gts)
	}
	ccm, _ := d["code_challenge_methods_supported"].([]any)
	if len(ccm) != 1 || ccm[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %+v, want [S256]", ccm)
	}
}
```

- [ ] **Step 11:** Run all tests + build:

```
cd /Users/jacinta/Source/herald && go build ./... && go test ./...
```

Expected: all `ok`.

- [ ] **Step 12:** Commit Task 4:

```
cd /Users/jacinta/Source/herald && git add internal/store internal/oidc cmd/herald && git commit -m "feat(oidc): /authorize endpoint with PKCE S256 + authz_code persistence"
```

---

## Task 5: /token authz_code grant + PKCE verification — NEX-399

**Files:**
- Create: `internal/oidc/authz_code_grant.go`
- Create: `internal/oidc/authz_code_grant_test.go`
- Modify: `internal/oidc/agent_grant.go` (dispatch on grant_type)
- Modify: `cmd/herald/main.go` (wire authz_code grant into the token handler)

---

- [ ] **Step 1:** Update the existing `ServeToken` to dispatch on `grant_type`. Replace the `ServeToken` body in `internal/oidc/agent_grant.go` with:

```go
// ServeToken handles POST /token. Dispatches on grant_type to the appropriate
// branch. path-A adds the authorization_code grant alongside the jwt-bearer one.
func (g *AgentGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	switch r.Form.Get("grant_type") {
	case jwtBearerGrant:
		g.serveJWTBearer(w, r)
	case authorizationCodeGrant:
		if g.authzCode == nil {
			oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code not configured")
			return
		}
		g.authzCode.ServeToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "unknown grant_type")
	}
}

// serveJWTBearer is the original agent flow, now reached via dispatch.
func (g *AgentGrant) serveJWTBearer(w http.ResponseWriter, r *http.Request) {
	assertion := r.Form.Get("assertion")
	if assertion == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing assertion")
		return
	}
	tok, err := g.issue(r.Context(), assertion, requestTokenURL(r))
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "assertion rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	})
}
```

Also add the constant at the top of `agent_grant.go`:

```go
const authorizationCodeGrant = "authorization_code"
```

And add a new field on `AgentGrant`:

```go
type AgentGrant struct {
	p         *Provider
	id        IdentityResolver
	authzCode *AuthzCodeGrant
}
```

And a setter:

```go
// SetAuthzCodeGrant wires the authorization_code branch onto the dispatcher.
func (g *AgentGrant) SetAuthzCodeGrant(a *AuthzCodeGrant) { g.authzCode = a }
```

- [ ] **Step 2:** Create the authz_code grant. Write `internal/oidc/authz_code_grant.go`:

```go
package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// AuthzCodeGrant implements POST /token for grant_type=authorization_code.
// It authenticates the client (basic auth or POST body), atomically single-uses
// the code, verifies PKCE, and issues an access token with the human-token shape.
type AuthzCodeGrant struct {
	p       *Provider
	clients *ClientRegistry
	id      AuthzCodeIdentity
	store   store.Store
	now     func() time.Time
}

// AuthzCodeIdentity is the slice of identity.Service the grant needs to mint
// human tokens — fetch the human + their effective scopes.
type AuthzCodeIdentity interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
	IsActive(ctx context.Context, id string) bool
}

// NewAuthzCodeGrant wires the grant.
func NewAuthzCodeGrant(p *Provider, clients *ClientRegistry, id AuthzCodeIdentity, s store.Store) *AuthzCodeGrant {
	return &AuthzCodeGrant{p: p, clients: clients, id: id, store: s, now: time.Now}
}

// ServeToken handles a POST /token authorization_code request. Caller has
// already parsed the form.
func (g *AuthzCodeGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, err := readClientCreds(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if _, err := g.clients.VerifySecret(r.Context(), clientID, clientSecret); err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "bad client credentials")
		return
	}

	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")
	if code == "" || redirectURI == "" || codeVerifier == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing code, redirect_uri, or code_verifier")
		return
	}

	now := g.now().UTC()
	ac, err := g.store.ConsumeAuthzCode(r.Context(), code, now.Format(time.RFC3339))
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code unknown, used, or expired")
		return
	}

	// Bindings: client + redirect_uri must match what was issued.
	if ac.ClientID != clientID {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code was not issued to this client")
		return
	}
	if subtle.ConstantTimeCompare([]byte(ac.RedirectURI), []byte(redirectURI)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match code")
		return
	}

	// PKCE: SHA256(verifier) base64url-no-pad == challenge.
	sum := sha256.Sum256([]byte(codeVerifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(got), []byte(ac.CodeChallenge)) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}

	// Resolve the human, check active, mint token.
	human, err := g.id.GetUser(r.Context(), ac.HumanID)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "human not found")
		return
	}
	if human.Kind != store.KindHuman {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "subject is not a human")
		return
	}
	if !g.id.IsActive(r.Context(), human.ID) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "human inactive")
		return
	}

	// Scopes: intersect what the human has with what the code requested.
	effective, err := g.id.EffectiveScopes(r.Context(), human.ID)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "scope lookup failed")
		return
	}
	granted := intersect(effective, strings.Fields(ac.Scope))

	claims := map[string]any{
		"sub":   human.ID,
		"kind":  string(store.KindHuman),
		"org":   human.OrgID,
		"scope": strings.Join(granted, " "),
	}
	if human.CasketFingerprint != "" {
		claims["human_fp"] = human.CasketFingerprint
	}
	tok, err := g.p.SignToken(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "sign failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
		"scope":        strings.Join(granted, " "),
	})
}

// readClientCreds extracts (client_id, client_secret) from Basic auth header
// or POST body, per RFC 6749 §2.3.1.
func readClientCreds(r *http.Request) (string, string, error) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p, nil
	}
	id := r.Form.Get("client_id")
	sec := r.Form.Get("client_secret")
	if id == "" || sec == "" {
		return "", "", errors.New("missing client_id or client_secret")
	}
	return id, sec, nil
}

func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(a))
	for _, s := range a {
		set[s] = struct{}{}
	}
	var out []string
	for _, s := range b {
		if _, ok := set[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// silence unused-import warnings during early scaffolding
var _ = fmt.Sprintf
```

- [ ] **Step 3:** Write the authz_code_grant test. Create `internal/oidc/authz_code_grant_test.go`:

```go
package oidc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/loginui"
	heraldoidc "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

type fullStack struct {
	srv      *httptest.Server
	provider *heraldoidc.Provider
	humanID  string
	clientID string
	secret   string
}

func newFullStack(t *testing.T) fullStack {
	t.Helper()
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	org, _ := svc.CreateOrg(context.Background(), "acme")
	h, _ := svc.CreateHuman(context.Background(), org.ID, "alice")
	fast := identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
	_ = svc.SetHumanPassword(context.Background(), h.ID, "hunter22", fast)
	_ = svc.GrantScope(context.Background(), h.ID, "repo:read", "test")

	clients := heraldoidc.NewClientRegistry(s, fast)
	res, _ := clients.Create(context.Background(), heraldoidc.ClientCreate{
		ClientID: "cairn-native", Name: "cairn",
		RedirectURIs:  []string{"https://relier.example/cb"},
		AllowedScopes: []string{"repo:read", "repo:write"},
		FirstParty:    true,
	})

	_, priv, _ := ed25519.GenerateKey(nil)
	p, _ := heraldoidc.NewProvider(heraldoidc.Config{Issuer: "https://herald.test/", SigningKey: priv})
	agent := heraldoidc.NewAgentGrant(p, svc)
	authz := heraldoidc.NewAuthzCodeGrant(p, clients, svc, s)
	agent.SetAuthzCodeGrant(authz)
	p.SetTokenHandler(agent)

	mgr := session.NewManager(session.Config{Store: s})
	ui, _ := loginui.New(svc, mgr)
	authzHTTP := heraldoidc.NewAuthzHandler(clients, mgr, s)

	mux := http.NewServeMux()
	ui.Mount(mux)
	authzHTTP.Mount(mux)
	mux.Handle("/.well-known/", p.Handler())
	mux.Handle("/jwks", p.Handler())
	mux.Handle("/token", p.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return fullStack{srv: srv, provider: p, humanID: h.ID, clientID: "cairn-native", secret: res.ClientSecret}
}

func loginAndGetCode(t *testing.T, st fullStack, verifier string) string {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, _ := client.Get(st.srv.URL + "/login")
	resp.Body.Close()
	u, _ := url.Parse(st.srv.URL)
	var csrf string
	for _, c := range jar.Cookies(u) {
		if c.Name == "herald_login_csrf" {
			csrf = c.Value
		}
	}
	body := url.Values{"csrf": []string{csrf}, "user_id": []string{st.humanID}, "password": []string{"hunter22"}}
	resp, _ = client.PostForm(st.srv.URL+"/login", body)
	resp.Body.Close()

	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"client_id":             []string{st.clientID},
		"redirect_uri":          []string{"https://relier.example/cb"},
		"response_type":         []string{"code"},
		"scope":                 []string{"repo:read"},
		"state":                 []string{"xyz"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}
	resp, err := client.Get(st.srv.URL + "/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %q", resp.Header.Get("Location"))
	}
	return code
}

func TestToken_AuthzCode_HappyPath(t *testing.T) {
	st := newFullStack(t)
	verifier := "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	code := loginAndGetCode(t, st, verifier)

	body := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{"https://relier.example/cb"},
		"code_verifier": []string{verifier},
		"client_id":     []string{st.clientID},
		"client_secret": []string{st.secret},
	}
	resp, err := http.PostForm(st.srv.URL+"/token", body)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.AccessToken == "" || out.TokenType != "Bearer" {
		t.Fatalf("bad token response: %+v", out)
	}
	claims, err := st.provider.VerifyToken(out.AccessToken)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims["kind"] != "human" {
		t.Fatalf("kind = %v", claims["kind"])
	}
	if claims["sub"] != st.humanID {
		t.Fatalf("sub = %v", claims["sub"])
	}
	if !strings.Contains(out.Scope, "repo:read") {
		t.Fatalf("scope = %q", out.Scope)
	}
}

func TestToken_AuthzCode_PKCEFail(t *testing.T) {
	st := newFullStack(t)
	verifier := "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	code := loginAndGetCode(t, st, verifier)
	body := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{"https://relier.example/cb"},
		"code_verifier": []string{"wrong-verifier"},
		"client_id":     []string{st.clientID},
		"client_secret": []string{st.secret},
	}
	resp, _ := http.PostForm(st.srv.URL+"/token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestToken_AuthzCode_CodeIsSingleUse(t *testing.T) {
	st := newFullStack(t)
	verifier := "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	code := loginAndGetCode(t, st, verifier)
	body := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{"https://relier.example/cb"},
		"code_verifier": []string{verifier},
		"client_id":     []string{st.clientID},
		"client_secret": []string{st.secret},
	}
	resp1, _ := http.PostForm(st.srv.URL+"/token", body)
	resp1.Body.Close()
	if resp1.StatusCode != 200 {
		t.Fatalf("first exchange = %d", resp1.StatusCode)
	}
	resp2, _ := http.PostForm(st.srv.URL+"/token", body)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("second exchange status = %d, want 400", resp2.StatusCode)
	}
}

func TestToken_AuthzCode_WrongClientSecret(t *testing.T) {
	st := newFullStack(t)
	verifier := "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	code := loginAndGetCode(t, st, verifier)
	body := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{"https://relier.example/cb"},
		"code_verifier": []string{verifier},
		"client_id":     []string{st.clientID},
		"client_secret": []string{"wrong"},
	}
	resp, _ := http.PostForm(st.srv.URL+"/token", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
```

- [ ] **Step 4:** Run authz_code tests, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/oidc/ -run TestToken_AuthzCode
```

Expected output prefix: `ok`.

- [ ] **Step 5:** Wire the grant in `cmd/herald/main.go`. After the existing `provider.SetTokenHandler(oidc.NewAgentGrant(provider, idsvc))` line, refactor to:

```go
	agentGrant := oidc.NewAgentGrant(provider, idsvc)
	authzCodeGrant := oidc.NewAuthzCodeGrant(provider, clients, idsvc, st)
	agentGrant.SetAuthzCodeGrant(authzCodeGrant)
	provider.SetTokenHandler(agentGrant)
```

- [ ] **Step 6:** Run all tests + build:

```
cd /Users/jacinta/Source/herald && go build ./... && go test ./...
```

Expected: all `ok`.

- [ ] **Step 7:** Commit Task 5:

```
cd /Users/jacinta/Source/herald && git add internal/oidc cmd/herald && git commit -m "feat(oidc): /token authorization_code grant with PKCE verification + atomic single-use"
```

---

## Task 6: E2E browser-flow integration test + cairn-client wire-up sanity — NEX-400

**Files:**
- Create: `internal/e2e/path_a_e2e_test.go`
- Create: `scripts/path-a-smoke.sh`
- Modify: `docs/2026-05-31-herald-path-a-spec.md` (update the §11 "Initial cairn-native client_id" decision)

---

- [ ] **Step 1:** Create an end-to-end test that wires the full server like `cmd/herald/main.go` does and drives the full browser flow with a cookie jar. Write `internal/e2e/path_a_e2e_test.go`:

```go
package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/heraldauth"
	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/loginui"
	"github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/session"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// buildHerald constructs the same mux cmd/herald/main.go does — so the e2e
// test catches wiring regressions, not just unit-level slices.
func buildHerald(t *testing.T) (*httptest.Server, *oidc.Provider, *identity.Service, *oidc.ClientRegistry, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	idsvc := identity.New(s)
	clients := oidc.NewClientRegistry(s, identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32})

	_, priv, _ := ed25519.GenerateKey(nil)
	prov, _ := oidc.NewProvider(oidc.Config{Issuer: "https://herald.test/", SigningKey: priv})
	agent := oidc.NewAgentGrant(prov, idsvc)
	authzCode := oidc.NewAuthzCodeGrant(prov, clients, idsvc, s)
	agent.SetAuthzCodeGrant(authzCode)
	prov.SetTokenHandler(agent)

	adminToken := "admin-token-xyz"
	api := adminapi.New(idsvc, prov, clients, adminToken)
	mgr := session.NewManager(session.Config{Store: s})
	ui, _ := loginui.New(idsvc, mgr)
	authzHTTP := oidc.NewAuthzHandler(clients, mgr, s)

	mux := http.NewServeMux()
	ui.Mount(mux)
	authzHTTP.Mount(mux)
	mux.Handle("/.well-known/", prov.Handler())
	mux.Handle("/jwks", prov.Handler())
	mux.Handle("/token", prov.Handler())
	mux.Handle("/api/", api.Handler())

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, prov, idsvc, clients, adminToken
}

// TestE2E_PathA_FullBrowserFlow is the path-A acceptance test (DoD §10):
//   admin provisions human + sets password + registers client → human visits
//   relier → relier 302s to /authorize → herald 302s to /login → human posts
//   creds → herald 302s to /authorize → herald 302s back to relier with code →
//   relier POSTs /token with verifier + secret → access token verified by
//   heraldauth carries human's identity + org + scopes.
func TestE2E_PathA_FullBrowserFlow(t *testing.T) {
	srv, prov, idsvc, clients, _ := buildHerald(t)

	// Out-of-band provisioning (mirrors the admin REST calls a deployer makes).
	ctx := context.Background()
	org, _ := idsvc.CreateOrg(ctx, "acme")
	h, _ := idsvc.CreateHuman(ctx, org.ID, "alice")
	fast := identity.PasswordParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, HashLen: 32}
	if err := idsvc.SetHumanPassword(ctx, h.ID, "hunter22", fast); err != nil {
		t.Fatalf("setpw: %v", err)
	}
	_ = idsvc.GrantScope(ctx, h.ID, "repo:read", "test")
	_ = idsvc.GrantScope(ctx, h.ID, "repo:write", "test")

	res, err := clients.Create(ctx, oidc.ClientCreate{
		ClientID: "cairn-native-test", Name: "cairn native (test)",
		RedirectURIs:  []string{srv.URL + "/relier/callback"},
		AllowedScopes: []string{"repo:read", "repo:write"},
		FirstParty:    true,
	})
	if err != nil {
		t.Fatalf("client create: %v", err)
	}

	// "Browser" with a cookie jar.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 1. Relier-side: build the /authorize URL with PKCE.
	verifier := "verifier-43chars-for-pkce-XXXXXXXXXXXXXXXXX"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authzURL := srv.URL + "/authorize?" + url.Values{
		"client_id":             []string{"cairn-native-test"},
		"redirect_uri":          []string{srv.URL + "/relier/callback"},
		"response_type":         []string{"code"},
		"scope":                 []string{"repo:read repo:write"},
		"state":                 []string{"state-xyz"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}.Encode()

	// 2. First hit: not logged in → /login?return=…
	resp, err := client.Get(authzURL)
	if err != nil {
		t.Fatalf("authz get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 to /login, got %d", resp.StatusCode)
	}
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login?return=") {
		t.Fatalf("redirect = %q", resp.Header.Get("Location"))
	}

	// 3. GET /login to pick up csrf cookie.
	loginPath := resp.Header.Get("Location")
	resp, err = client.Get(srv.URL + loginPath)
	if err != nil {
		t.Fatalf("get login: %v", err)
	}
	resp.Body.Close()
	srvURL, _ := url.Parse(srv.URL)
	var csrf string
	for _, c := range jar.Cookies(srvURL) {
		if c.Name == "herald_login_csrf" {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("no csrf cookie")
	}

	// 4. Extract the return URL from the /login query string and POST creds.
	loginU, _ := url.Parse(loginPath)
	returnURL := loginU.Query().Get("return")
	form := url.Values{
		"csrf":     []string{csrf},
		"user_id":  []string{h.ID},
		"password": []string{"hunter22"},
		"return":   []string{returnURL},
	}
	resp, err = client.PostForm(srv.URL+"/login", form)
	if err != nil {
		t.Fatalf("post login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login post status = %d", resp.StatusCode)
	}

	// 5. Follow back into /authorize.
	resp, err = client.Get(srv.URL + resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("re-authz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authz-after-login status = %d", resp.StatusCode)
	}
	cbLoc, _ := url.Parse(resp.Header.Get("Location"))
	if cbLoc.Query().Get("state") != "state-xyz" {
		t.Fatalf("state mismatch: %q", cbLoc.Query().Get("state"))
	}
	code := cbLoc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %q", cbLoc)
	}

	// 6. Relier-side: POST /token.
	tokBody := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{code},
		"redirect_uri":  []string{srv.URL + "/relier/callback"},
		"code_verifier": []string{verifier},
		"client_id":     []string{"cairn-native-test"},
		"client_secret": []string{res.ClientSecret},
	}
	resp, err = http.PostForm(srv.URL+"/token", tokBody)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("token status = %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.AccessToken == "" {
		t.Fatal("no access token")
	}

	// 7. heraldauth verifies the token end-to-end against the JWKS endpoint.
	v, err := heraldauth.New(ctx, heraldauth.Config{
		Issuer:  prov.Issuer(),
		JWKSURL: srv.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("heraldauth: %v", err)
	}
	id, err := v.Verify(ctx, out.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Subject != h.ID {
		t.Fatalf("subject = %s, want %s", id.Subject, h.ID)
	}
	if id.Kind != "human" {
		t.Fatalf("kind = %s, want human", id.Kind)
	}
	if id.Org != org.ID {
		t.Fatalf("org = %s, want %s", id.Org, org.ID)
	}
	if !id.HasScope("repo:read") || !id.HasScope("repo:write") {
		t.Fatalf("missing scopes: %v", id.Scopes)
	}
}

// TestE2E_PathA_AgentGrantStillWorks asserts the jwt-bearer flow is unaffected
// by the new dispatch.
func TestE2E_PathA_AgentGrantStillWorks(t *testing.T) {
	srv, _, _, _, _ := buildHerald(t)
	// Wrong grant_type should yield 400 unsupported_grant_type, not 500/panic.
	resp, err := http.PostForm(srv.URL+"/token", url.Values{"grant_type": []string{"bogus"}})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
```

- [ ] **Step 2:** Run the e2e test, expect PASS:

```
cd /Users/jacinta/Source/herald && go test ./internal/e2e/ -v
```

Expected output prefix: `=== RUN   TestE2E_PathA_FullBrowserFlow` ending with `--- PASS:` and `ok`.

- [ ] **Step 3:** Write a smoke script for manual cairn-native bring-up. Write `scripts/path-a-smoke.sh`:

```bash
#!/usr/bin/env bash
# path-a-smoke.sh — manual exercise of the path-A flow against a running herald.
# Requires: curl, jq, openssl, python3 (for url-safe b64).
# Env: HERALD=http://localhost:8099  ADMIN_TOKEN=…  ORG_ID=…  HUMAN_ID=…
set -euo pipefail

: "${HERALD:?set HERALD to the herald base URL}"
: "${ADMIN_TOKEN:?set ADMIN_TOKEN}"
: "${ORG_ID:?set ORG_ID}"
: "${HUMAN_ID:?set HUMAN_ID}"

echo "==> set password for $HUMAN_ID"
curl -sf -X POST "$HERALD/api/humans/$HUMAN_ID/password" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"password":"smoke-test-password-22"}' | jq

echo "==> register cairn-native test client"
SECRET=$(curl -sf -X POST "$HERALD/api/oidc/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":\"cairn-native-smoke\",\"name\":\"smoke\",\"redirect_uris\":[\"$HERALD/relier/cb\"],\"allowed_scopes\":[\"repo:read\"],\"first_party\":true}" \
  | jq -r .client_secret)
echo "client_secret=$SECRET"

echo "==> PKCE pair"
VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | python3 -c "import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b'=').decode())")
echo "verifier=$VERIFIER"
echo "challenge=$CHALLENGE"

echo "==> open this URL in a browser, sign in, copy the 'code' from the redirect:"
echo "$HERALD/authorize?client_id=cairn-native-smoke&redirect_uri=$HERALD/relier/cb&response_type=code&scope=repo:read&state=smoke-state&code_challenge=$CHALLENGE&code_challenge_method=S256"

read -rp "paste code: " CODE

echo "==> exchange code for token"
curl -sf -X POST "$HERALD/token" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=$HERALD/relier/cb" \
  -d "code_verifier=$VERIFIER" \
  -d "client_id=cairn-native-smoke" \
  -d "client_secret=$SECRET" | jq
```

Then `chmod +x /Users/jacinta/Source/herald/scripts/path-a-smoke.sh`.

- [ ] **Step 4:** Update the spec's open question §11 about `cairn-native client_id` to record the decision. Edit `docs/2026-05-31-herald-path-a-spec.md` and replace the bullet starting with `**Initial cairn-native client_id**` with:

```
- **Initial cairn-native client_id** — DECIDED (NEX-400): per-deployment, of the form `cairn-native-<host>` (e.g. `cairn-native-cwb`). Each deployment registers its own client via admin REST; no shared global id.
```

- [ ] **Step 5:** Run the full test suite one more time:

```
cd /Users/jacinta/Source/herald && go test ./... && go build ./...
```

Expected output: all `ok`, no build errors.

- [ ] **Step 6:** Commit Task 6:

```
cd /Users/jacinta/Source/herald && git add internal/e2e scripts/path-a-smoke.sh docs/2026-05-31-herald-path-a-spec.md && git commit -m "test(e2e): full path-A browser-flow integration test + smoke script"
```

- [ ] **Step 7:** Self-check that the path-A DoD (spec §10) is met: a human opens cairn-native, lands on herald `/login`, signs in, gets redirected back with an access token, and heraldauth verifies it carrying the human's identity + org + scopes. The e2e test in Step 1 asserts each of these in code; running it green is the DoD.

---

## Self-review notes

- Type signatures match across tasks: `oidc.NewClientRegistry(store.Store, identity.PasswordParams)`, `oidc.NewAuthzHandler(*ClientRegistry, *session.Manager, store.Store)`, `oidc.NewAuthzCodeGrant(*Provider, *ClientRegistry, AuthzCodeIdentity, store.Store)`, and `AgentGrant.SetAuthzCodeGrant(*AuthzCodeGrant)` are consistent everywhere they're used.
- Migration ordering: Task 1 adds `password_hash` and the three new tables via the embedded `schema_path_a.sql` + ALTER guards. Task 2 reads sessions (already created). Task 3 reads `oidc_client` (already created). Task 4 reads `authz_code` (already created). No reorder hazard.
- Spec coverage: human creds + admin password REST (§3, §7, §10.2) → Task 1; sessions + login UI + CSRF (§3, §5a, §7, §10.3) → Task 2; oidc_clients + admin REST + one-time secret (§3, §7, §10.4) → Task 3; /authorize + PKCE S256 + login-bounce + auto-consent + discovery updates (§5a, §7, §10.5) → Task 4; /token authz_code branch + PKCE verify + atomic single-use + token shape (§4, §5a, §6, §10.6) → Task 5; full e2e + cairn-native client_id decision (§10.7, §11) → Task 6.
- The `var _ = context.Background` style placeholders in `authz.go` and `authz_code_grant.go` should be removed by the implementer when the imports are actually used end-to-end; they're there to keep early TDD steps compile-clean and explicit.
