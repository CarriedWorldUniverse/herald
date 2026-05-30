# herald org-ownership + invites + tenant model — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace herald's static-admin-token provisioning with user-identity-driven org governance — a user creates + owns an org (with a slug under a hosted/trusted tier), verifies its domain, invites others via scoped links (out-of-band or branded email), and provisions within the org by org_role.

**Architecture:** Extends the existing herald binary (store + identity + oidc + adminapi). Additive SQLite migration; org-scoped endpoints gated on the caller's herald-JWT org_role (server-side from the record); invite links with a domain/email-list policy; per-host short-rolling certs are an ops concern, not in this plan.

**Tech Stack:** Go 1.26, existing herald deps (modernc.org/sqlite, go-jose/v4, casket-go). Depends on the path-A amendment (email + email_verified + Notifier).

---

## Dependency on the path-A amendment (READ FIRST)

This plan layers on the **path-A amendment** (spec §9), which adds to the *same* `user` table:

- `user.email TEXT NULL` — the login identity and the value invite policies match against.
- `user.email_verified TEXT NULL` — a timestamp; non-null means the email is verified.
- A pluggable **`Notifier` interface** — `Send(ctx, msg)` that sends from a *sending identity* (the platform domain for account mail, the org's verified domain for org invites).

**Sequencing:** path-A (with this amendment) lands **before** this plan. Where a task needs a path-A primitive, this plan does ONE of:

- **(a) Assume it from amended path-A** — the `email` / `email_verified` columns and the token claims `email` / `email_verified` are assumed present. Tasks 2 and 5 read them.
- **(b) Define a minimal local stub + a clear "replace when path-A lands" note** — the `Notifier` interface is **declared locally in this plan** (Task 6) as a herald-internal seam with a no-op/capture default, so org-ownership compiles and tests pass even if the path-A ESP backend is not yet wired. When path-A lands its canonical `Notifier`, Task 6's local interface is replaced by an import; the call site is unchanged.

**To keep the migration ordering clean (spec §11):** this plan's migration (Task 1) is written to be *idempotent and additive over* the path-A columns — it does NOT add `email` / `email_verified` (path-A owns those). If a worker runs this plan against a herald that does NOT yet have the path-A columns, Task 1's migration still applies (it touches only org-ownership columns/tables); Tasks 2 and 5 read `email` / `email_verified` from the **token claims**, not the store row, so they do not hard-depend on the path-A store columns existing — see each task's "path-A note".

**Do NOT re-plan path-A here.** This plan consumes a verified-user identity; it does not build email verification or 2FA.

---

## Conventions used in every task

- **TDD:** failing test → `go test` (expect FAIL) → implement → `go test` (expect PASS) → commit. Every test step shows the full test code; every command step shows the exact command + an expected output prefix.
- **Module root:** all `go` commands run from `/Users/jacinta/Source/herald` (Task 8 runs from `/Users/jacinta/Source/cwb-conformance`).
- **Commit prefixes:** `nex-414:` … `nex-421:` per task. Commit messages end with the Co-Authored-By trailer the repo uses; shown once in Task 1, abbreviated as `<trailer>` thereafter.
- **Time:** timestamps are SQLite `datetime('now')` strings (the existing convention). A non-null `*_at`/`*_verified_at` means "happened".

---

# Task 1 — Schema migration (NEX-414)

**Goal:** Extend the schema additively: `user.org_id` nullable + `user.org_role`; `org.slug`/`tier`/`domain`/`domain_verified_at` with `UNIQUE(tier,slug)`; new `org_domain_challenge` + `org_invite` tables; a reserved-slug constant. Backfill existing rows. Add the store types + methods Tasks 2–7 call.

**Path-A note:** This migration does NOT touch `email`/`email_verified` (path-A owns them). It is safe to apply before or after path-A's migration.

### Migration strategy

`store.Open` applies `schema.sql` (a bag of `CREATE TABLE IF NOT EXISTS`). SQLite's `CREATE TABLE IF NOT EXISTS` will **not** add columns to an existing table, and `ALTER TABLE ... ADD COLUMN` errors if the column already exists. So we add a small **idempotent migrate step** that runs after the schema apply: it inspects `PRAGMA table_info` and adds any missing columns. New tables go in `schema.sql` directly (IF NOT EXISTS is enough). The `org` rebuild for `UNIQUE(tier,slug)` is handled by adding the columns then creating a unique index (a unique *index* is addable without a table rebuild, unlike a table-level `UNIQUE` constraint).

### Steps

- [ ] **1.1 — Write the failing migration test.** Create `/Users/jacinta/Source/herald/internal/store/migrate_test.go`:

```go
package store_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestMigration_OrgOwnershipColumnsAndTables(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Org carries slug/tier/domain after migration; defaults applied.
	org, err := s.CreateOrgWithSlug(ctx, "Acme Inc", "acme", "hosted")
	if err != nil {
		t.Fatalf("CreateOrgWithSlug: %v", err)
	}
	if org.Slug != "acme" || org.Tier != "hosted" {
		t.Fatalf("bad org slug/tier: %+v", org)
	}
	if org.Domain != "" || org.DomainVerifiedAt != "" {
		t.Fatalf("new org should have no verified domain: %+v", org)
	}

	// A user can be created orgless (org_id NULL) with no role.
	u, err := s.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	if err != nil {
		t.Fatalf("CreateUser orgless: %v", err)
	}
	if u.OrgID != "" || u.OrgRole != "" {
		t.Fatalf("orgless user should have empty org/role: %+v", u)
	}

	// SetUserOrg attaches the user to the org with a role.
	if err := s.SetUserOrg(ctx, u.ID, org.ID, store.RoleOwner); err != nil {
		t.Fatalf("SetUserOrg: %v", err)
	}
	got, _ := s.GetUser(ctx, u.ID)
	if got.OrgID != org.ID || got.OrgRole != store.RoleOwner {
		t.Fatalf("user not attached: %+v", got)
	}

	// slug+tier uniqueness within a tier.
	if _, err := s.CreateOrgWithSlug(ctx, "Other", "acme", "hosted"); err == nil {
		t.Fatal("duplicate slug within tier should fail")
	}
	// same slug, different tier, is allowed.
	if _, err := s.CreateOrgWithSlug(ctx, "Acme Trusted", "acme", "trusted"); err != nil {
		t.Fatalf("same slug different tier should be allowed: %v", err)
	}
}
```

- [ ] **1.2 — Run, expect FAIL** (types/methods don't exist):

```
go test ./internal/store/ -run TestMigration_OrgOwnership
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/store` (compile failure: `CreateOrgWithSlug`, `RoleOwner`, `OrgRole`, etc. undefined).

- [ ] **1.3 — Extend `schema.sql`.** Edit `/Users/jacinta/Source/herald/internal/store/schema.sql`. Append (do NOT modify the existing `CREATE TABLE` bodies — column adds happen in the migrate step so existing DBs upgrade):

```sql
-- org-ownership (NEX-414): slug+tier uniqueness, domain-challenge + invite tables.
-- New columns on existing tables (org.slug/tier/domain/domain_verified_at,
-- user.org_role, user.org_id-nullability) are added idempotently by migrate.go
-- so existing databases upgrade in place.

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_tier_slug ON org(tier, slug);

CREATE TABLE IF NOT EXISTS org_domain_challenge (
  org_id      TEXT NOT NULL REFERENCES org(id),
  domain      TEXT NOT NULL,                 -- the domain being claimed (e.g. acme.com)
  txt_token   TEXT NOT NULL,                 -- value to publish at _herald-challenge.<domain>
  verified_at TEXT NULL,
  created_at  TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org_id, domain)
);

CREATE TABLE IF NOT EXISTS org_invite (
  token        TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL REFERENCES org(id),
  role         TEXT NOT NULL DEFAULT 'member',
  policy_type  TEXT NOT NULL,                -- 'domain' | 'email_list'
  policy_value TEXT NOT NULL,                -- domain string, OR JSON array of emails
  delivery     TEXT NOT NULL DEFAULT 'link', -- 'link' | 'email'
  expires_at   TEXT NULL,
  max_uses     INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited within policy + expiry
  uses         INTEGER NOT NULL DEFAULT 0,
  created_by   TEXT NOT NULL REFERENCES user(id),
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at   TEXT NULL
);
CREATE INDEX IF NOT EXISTS idx_org_invite_org ON org_invite(org_id);
```

Note: the existing `org` and `user` `CREATE TABLE IF NOT EXISTS` bodies stay as-is. For a *brand-new* DB, the migrate step (1.5) still runs and adds the new columns to the freshly-created tables — so fresh and upgraded DBs converge on the same shape.

- [ ] **1.4 — Add the reserved-slug constant + validation helper.** Create `/Users/jacinta/Source/herald/internal/store/slug.go`:

```go
package store

// ReservedSlugs are slug labels that may never be claimed by an org — they
// collide with platform hostnames / tier names. Checked at org-create time.
var ReservedSlugs = map[string]bool{
	"hosted": true, "trusted": true, "www": true, "api": true,
	"herald": true, "cairn": true, "ledger": true, "admin": true,
	"mail": true, "app": true, "auth": true, "gateway": true,
}

// Tier values for an org's tenant namespace.
const (
	TierHosted  = "hosted"
	TierTrusted = "trusted"
)

// Org roles within an org's governance.
const (
	RoleOwner  = "owner"
	RoleMember = "member"
)

// Invite policy types and delivery modes.
const (
	PolicyDomain    = "domain"
	PolicyEmailList = "email_list"
	DeliveryLink    = "link"
	DeliveryEmail   = "email"
)
```

- [ ] **1.5 — Add the idempotent column-adder.** Create `/Users/jacinta/Source/herald/internal/store/migrate.go`:

```go
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// migrate brings an existing database forward to the org-ownership schema by
// adding any columns that schema.sql's CREATE-IF-NOT-EXISTS bodies cannot add
// to a pre-existing table. Idempotent: it only adds a column when absent.
func migrate(ctx context.Context, db *sql.DB) error {
	type colSpec struct{ table, col, ddl string }
	want := []colSpec{
		{"org", "slug", "ALTER TABLE org ADD COLUMN slug TEXT NOT NULL DEFAULT ''"},
		{"org", "tier", "ALTER TABLE org ADD COLUMN tier TEXT NOT NULL DEFAULT 'hosted'"},
		{"org", "domain", "ALTER TABLE org ADD COLUMN domain TEXT NULL"},
		{"org", "domain_verified_at", "ALTER TABLE org ADD COLUMN domain_verified_at TEXT NULL"},
		{"user", "org_role", "ALTER TABLE user ADD COLUMN org_role TEXT NULL"},
	}
	for _, w := range want {
		has, err := hasColumn(ctx, db, w.table, w.col)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.ExecContext(ctx, w.ddl); err != nil {
			return fmt.Errorf("migrate %s.%s: %w", w.table, w.col, err)
		}
	}
	// Backfill: an existing org with an empty slug gets its id as a deterministic
	// placeholder slug so the UNIQUE(tier,slug) index never collides on '' for
	// pre-migration rows. New orgs always supply a real slug.
	if _, err := db.ExecContext(ctx,
		`UPDATE org SET slug = id WHERE slug = '' OR slug IS NULL`); err != nil {
		return fmt.Errorf("migrate backfill org.slug: %w", err)
	}
	return nil
}

// hasColumn reports whether table has a column named col (via PRAGMA table_info).
func hasColumn(ctx context.Context, db *sql.DB, table, col string) (bool, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("table_info(%s): %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, nil
		}
	}
	return false, rows.Err()
}
```

Note on `user.org_id` nullability: the existing column is `TEXT NOT NULL REFERENCES org(id)`. SQLite cannot drop a `NOT NULL` constraint via `ALTER`. The migrate step does NOT rebuild `user`; instead, the store **writes `org_id` as SQL NULL when empty** (see 1.7) and a fresh DB created from the (unchanged) `schema.sql` keeps `NOT NULL`. To make orgless users work on **fresh** DBs, change the `user.org_id` line in `schema.sql` from `NOT NULL` to nullable in 1.6.

- [ ] **1.6 — Make `user.org_id` nullable in the fresh-DB schema.** Edit `/Users/jacinta/Source/herald/internal/store/schema.sql`, the `user` table:

Change:
```sql
  org_id             TEXT NOT NULL REFERENCES org(id),
```
to:
```sql
  org_id             TEXT NULL REFERENCES org(id),   -- nullable: orgless transient (NEX-414)
```

(Existing file DBs keep their old `NOT NULL` on `org_id`; that is acceptable because the bootstrap path always seeds the first user orgless via a fresh DB after this lands, and pre-migration prod rows already have an org. The store-layer null-write in 1.7 + the fresh schema cover the orgless case going forward.)

- [ ] **1.7 — Wire the migrate call + extend store types/methods.** Edit `/Users/jacinta/Source/herald/internal/store/sqlite.go`.

First, call `migrate` in `Open`, right after the schema apply (inside `Open`, after the `s.db.Exec(schemaSQL)` block):

```go
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: apply schema: %w", err)
	}
	if err := migrate(context.Background(), db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: migrate: %w", err)
	}
```

(Add `"context"` to the import block if not present — it is not currently imported in sqlite.go, so add it.)

Replace `CreateOrg` and `GetOrg`, and update `CreateUser`/`scanUserRow`/`userSelect`, as follows. Replace the existing `CreateOrg`:

```go
func (s *SQLite) CreateOrg(ctx context.Context, name string) (Org, error) {
	// Back-compat shim: a name-only org under the hosted tier with the id as slug.
	o := Org{ID: newID()}
	return s.CreateOrgWithSlug(ctx, name, o.ID, TierHosted)
}

// CreateOrgWithSlug creates an org with an explicit DNS-safe slug under a tier.
// Slug validation + reserved-list checks are the identity layer's job; the
// store enforces only UNIQUE(tier, slug) via the index.
func (s *SQLite) CreateOrgWithSlug(ctx context.Context, name, slug, tier string) (Org, error) {
	if tier == "" {
		tier = TierHosted
	}
	o := Org{ID: newID(), Name: name, Slug: slug, Tier: tier, Status: StatusActive}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org (id, name, slug, tier, status) VALUES (?, ?, ?, ?, ?)`,
		o.ID, o.Name, o.Slug, o.Tier, string(o.Status))
	if err != nil {
		return Org{}, fmt.Errorf("CreateOrgWithSlug: %w", err)
	}
	return s.GetOrg(ctx, o.ID)
}
```

Replace `GetOrg`'s SELECT + scan to include the new columns:

```go
func (s *SQLite) GetOrg(ctx context.Context, id string) (Org, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, orgSelect+` WHERE id = ?`, id))
}

// GetOrgBySlug resolves an org by its (tier, slug) tenant coordinates.
func (s *SQLite) GetOrgBySlug(ctx context.Context, tier, slug string) (Org, error) {
	return s.scanOrg(s.db.QueryRowContext(ctx, orgSelect+` WHERE tier = ? AND slug = ?`, tier, slug))
}

const orgSelect = `SELECT id, name, slug, tier, domain, domain_verified_at, status, created_at FROM org`

func (s *SQLite) scanOrg(row scanner) (Org, error) {
	var o Org
	var status string
	var domain, dva sql.NullString
	err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.Tier, &domain, &dva, &status, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, fmt.Errorf("scanOrg: %w", err)
	}
	o.Domain = domain.String
	o.DomainVerifiedAt = dva.String
	o.Status = Status(status)
	return o, nil
}
```

Update `CreateUser`'s INSERT to include `org_role` and to NULL-out `org_id` when empty:

```go
func (s *SQLite) CreateUser(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		u.ID = newID()
	}
	if u.Status == "" {
		u.Status = StatusActive
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user (id, org_id, org_role, kind, display_name, status,
		                  login_secret, casket_pubkey, casket_fingerprint, responsible_human)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, nullStr(u.OrgID), nullStr(u.OrgRole), string(u.Kind), u.DisplayName, string(u.Status),
		nullStr(u.LoginSecret), nullBytes(u.CasketPubkey), nullStr(u.CasketFingerprint), nullStr(u.ResponsibleHuman))
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	return s.GetUser(ctx, u.ID)
}
```

Update `userSelect` + `scanUserRow` to carry `org_role`:

```go
const userSelect = `SELECT id, org_id, org_role, kind, display_name, status,
	login_secret, casket_pubkey, casket_fingerprint, responsible_human, created_at FROM user`
```

```go
func scanUserRow(row scanner) (User, error) {
	var u User
	var kind, status string
	var orgID, orgRole, login, fp, resp sql.NullString
	var pub []byte
	if err := row.Scan(&u.ID, &orgID, &orgRole, &kind, &u.DisplayName, &status,
		&login, &pub, &fp, &resp, &u.CreatedAt); err != nil {
		return User{}, err
	}
	u.OrgID = orgID.String
	u.OrgRole = orgRole.String
	u.Kind = Kind(kind)
	u.Status = Status(status)
	u.LoginSecret = login.String
	u.CasketPubkey = pub
	u.CasketFingerprint = fp.String
	u.ResponsibleHuman = resp.String
	return u, nil
}
```

Add the new store methods (append to sqlite.go):

```go
// SetUserOrg attaches a user to an org with a role (used by org-create + invite
// accept). Pass empty role to detach is not supported in MVP.
func (s *SQLite) SetUserOrg(ctx context.Context, userID, orgID, role string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE user SET org_id = ?, org_role = ? WHERE id = ?`, orgID, role, userID)
	if err != nil {
		return fmt.Errorf("SetUserOrg: %w", err)
	}
	return mustAffect(res)
}

// SetOrgDomain records a verified domain on the org.
func (s *SQLite) SetOrgDomain(ctx context.Context, orgID, domain string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE org SET domain = ?, domain_verified_at = datetime('now') WHERE id = ?`,
		domain, orgID)
	if err != nil {
		return fmt.Errorf("SetOrgDomain: %w", err)
	}
	return mustAffect(res)
}

// CreateDomainChallenge stores a pending TXT challenge for an org+domain,
// replacing any prior unverified challenge for the same pair.
func (s *SQLite) CreateDomainChallenge(ctx context.Context, orgID, domain, txtToken string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO org_domain_challenge (org_id, domain, txt_token)
		VALUES (?, ?, ?)
		ON CONFLICT(org_id, domain) DO UPDATE SET txt_token = excluded.txt_token, verified_at = NULL`,
		orgID, domain, txtToken)
	if err != nil {
		return fmt.Errorf("CreateDomainChallenge: %w", err)
	}
	return nil
}

// GetDomainChallenge returns the pending challenge for an org+domain.
func (s *SQLite) GetDomainChallenge(ctx context.Context, orgID, domain string) (DomainChallenge, error) {
	var c DomainChallenge
	var verified sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT org_id, domain, txt_token, verified_at, created_at FROM org_domain_challenge WHERE org_id = ? AND domain = ?`,
		orgID, domain).Scan(&c.OrgID, &c.Domain, &c.TxtToken, &verified, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DomainChallenge{}, ErrNotFound
	}
	if err != nil {
		return DomainChallenge{}, fmt.Errorf("GetDomainChallenge: %w", err)
	}
	c.VerifiedAt = verified.String
	return c, nil
}

// CreateInvite stores a new invite row.
func (s *SQLite) CreateInvite(ctx context.Context, inv Invite) (Invite, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO org_invite (token, org_id, role, policy_type, policy_value, delivery, expires_at, max_uses, uses, created_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		inv.Token, inv.OrgID, inv.Role, inv.PolicyType, inv.PolicyValue, inv.Delivery,
		nullStr(inv.ExpiresAt), inv.MaxUses, inv.CreatedBy)
	if err != nil {
		return Invite{}, fmt.Errorf("CreateInvite: %w", err)
	}
	return s.GetInvite(ctx, inv.Token)
}

// GetInvite returns an invite by token.
func (s *SQLite) GetInvite(ctx context.Context, token string) (Invite, error) {
	var inv Invite
	var expires, revoked sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT token, org_id, role, policy_type, policy_value, delivery, expires_at, max_uses, uses, created_by, created_at, revoked_at
		 FROM org_invite WHERE token = ?`, token).
		Scan(&inv.Token, &inv.OrgID, &inv.Role, &inv.PolicyType, &inv.PolicyValue, &inv.Delivery,
			&expires, &inv.MaxUses, &inv.Uses, &inv.CreatedBy, &inv.CreatedAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	if err != nil {
		return Invite{}, fmt.Errorf("GetInvite: %w", err)
	}
	inv.ExpiresAt = expires.String
	inv.RevokedAt = revoked.String
	return inv, nil
}

// ListInvites returns the org's invites (newest first), including revoked.
func (s *SQLite) ListInvites(ctx context.Context, orgID string) ([]Invite, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token, org_id, role, policy_type, policy_value, delivery, expires_at, max_uses, uses, created_by, created_at, revoked_at
		 FROM org_invite WHERE org_id = ? ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, fmt.Errorf("ListInvites: %w", err)
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		var inv Invite
		var expires, revoked sql.NullString
		if err := rows.Scan(&inv.Token, &inv.OrgID, &inv.Role, &inv.PolicyType, &inv.PolicyValue, &inv.Delivery,
			&expires, &inv.MaxUses, &inv.Uses, &inv.CreatedBy, &inv.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		inv.ExpiresAt = expires.String
		inv.RevokedAt = revoked.String
		out = append(out, inv)
	}
	return out, rows.Err()
}

// IncrementInviteUses atomically bumps uses (called on a successful accept).
func (s *SQLite) IncrementInviteUses(ctx context.Context, token string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE org_invite SET uses = uses + 1 WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("IncrementInviteUses: %w", err)
	}
	return mustAffect(res)
}

// RevokeInvite marks an invite revoked (soft delete).
func (s *SQLite) RevokeInvite(ctx context.Context, orgID, token string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE org_invite SET revoked_at = datetime('now') WHERE token = ? AND org_id = ?`, token, orgID)
	if err != nil {
		return fmt.Errorf("RevokeInvite: %w", err)
	}
	return mustAffect(res)
}
```

- [ ] **1.8 — Extend store.go types + the Store interface.** Edit `/Users/jacinta/Source/herald/internal/store/store.go`.

Add fields to `Org`:

```go
type Org struct {
	ID               string
	Name             string
	Slug             string
	Tier             string
	Domain           string // verified email/sending domain; "" until verified
	DomainVerifiedAt string // timestamp; "" until verified
	Status           Status
	CreatedAt        string
}
```

Add `OrgRole` to `User` (after `OrgID`):

```go
	OrgID             string
	OrgRole           string // 'owner'|'member'; "" when orgless
```

Add the new record types (after `ScopeGrant`):

```go
// DomainChallenge is a pending domain-ownership proof for an org.
type DomainChallenge struct {
	OrgID      string
	Domain     string
	TxtToken   string
	VerifiedAt string
	CreatedAt  string
}

// Invite is a reusable, scoped invitation link into an org.
type Invite struct {
	Token       string
	OrgID       string
	Role        string
	PolicyType  string // 'domain' | 'email_list'
	PolicyValue string // domain string OR JSON array of emails
	Delivery    string // 'link' | 'email'
	ExpiresAt   string // "" = no expiry
	MaxUses     int    // 0 = unlimited
	Uses        int
	CreatedBy   string
	CreatedAt   string
	RevokedAt   string // "" = live
}
```

Add the methods to the `Store` interface (inside the `Store` interface block):

```go
	// Orgs (org-ownership).
	CreateOrgWithSlug(ctx context.Context, name, slug, tier string) (Org, error)
	GetOrgBySlug(ctx context.Context, tier, slug string) (Org, error)
	SetUserOrg(ctx context.Context, userID, orgID, role string) error
	SetOrgDomain(ctx context.Context, orgID, domain string) error

	// Domain challenges.
	CreateDomainChallenge(ctx context.Context, orgID, domain, txtToken string) error
	GetDomainChallenge(ctx context.Context, orgID, domain string) (DomainChallenge, error)

	// Invites.
	CreateInvite(ctx context.Context, inv Invite) (Invite, error)
	GetInvite(ctx context.Context, token string) (Invite, error)
	ListInvites(ctx context.Context, orgID string) ([]Invite, error)
	IncrementInviteUses(ctx context.Context, token string) error
	RevokeInvite(ctx context.Context, orgID, token string) error
```

- [ ] **1.9 — Run, expect PASS:**

```
go test ./internal/store/
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/store`

- [ ] **1.10 — Build the whole module (existing callers still compile):**

```
go build ./...
```
Expected output prefix: (no output; exit 0).

- [ ] **1.11 — Commit:**

```
git commit -am "nex-414: additive org-ownership migration — nullable org_id, org_role, org slug/tier/domain, domain-challenge + invite tables

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# Task 2 — Create org by user token + slug/tier validation (NEX-415)

**Goal:** Re-gate `POST /api/orgs` from the admin token to a *user* token. Body `{name, slug, tier?}`. Validate the slug (lowercase alphanumeric + hyphen, ≤63), reject reserved + duplicate-within-tier, default tier `hosted`. Set the caller's `org_id` + `org_role=owner`. Reject if the caller already belongs to an org.

**Path-A note:** The caller must be `kind=human` and `email_verified`. The handler reads `email_verified` from the **token claims** (key `"email_verified"`), so it does not hard-depend on the path-A store column. If the claim is absent (path-A not yet wired), the handler rejects with 403 `email not verified` — this is the correct safe default; once path-A issues tokens with the claim, verified users pass.

### New identity-layer methods

Org governance lives in `identity` (the domain layer). Add `CreateOrgOwned` (validates slug, creates org, attaches caller as owner) and a slug validator.

### Steps

- [ ] **2.1 — Failing identity test.** Create `/Users/jacinta/Source/herald/internal/identity/org_test.go`:

```go
package identity_test

import (
	"context"
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

func TestCreateOrgOwned(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()

	// An orgless human.
	u, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})

	org, err := svc.CreateOrgOwned(ctx, u.ID, "Acme Inc", "acme", "")
	if err != nil {
		t.Fatalf("CreateOrgOwned: %v", err)
	}
	if org.Slug != "acme" || org.Tier != store.TierHosted {
		t.Fatalf("bad org: %+v", org)
	}
	got, _ := st.GetUser(ctx, u.ID)
	if got.OrgID != org.ID || got.OrgRole != store.RoleOwner {
		t.Fatalf("caller not owner: %+v", got)
	}

	// Already in an org -> rejected.
	if _, err := svc.CreateOrgOwned(ctx, u.ID, "Other", "other", ""); err == nil {
		t.Fatal("creating a second org should fail (single-org invariant)")
	}
}

func TestCreateOrgOwned_SlugValidation(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	mk := func() string {
		u, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "u"})
		return u.ID
	}
	bad := []string{"", "UPPER", "has space", "under_score", "ends-", "-starts", "a..b", string(make([]byte, 64))}
	for _, slug := range bad {
		if _, err := svc.CreateOrgOwned(ctx, mk(), "n", slug, ""); err == nil {
			t.Fatalf("slug %q should be rejected", slug)
		}
	}
	// reserved.
	if _, err := svc.CreateOrgOwned(ctx, mk(), "n", "admin", ""); err == nil {
		t.Fatal("reserved slug 'admin' should be rejected")
	}
	// duplicate within tier.
	if _, err := svc.CreateOrgOwned(ctx, mk(), "n", "dup", "hosted"); err != nil {
		t.Fatalf("first dup: %v", err)
	}
	if _, err := svc.CreateOrgOwned(ctx, mk(), "n", "dup", "hosted"); err == nil {
		t.Fatal("duplicate slug within tier should be rejected")
	}
}
```

- [ ] **2.2 — Run, expect FAIL:**

```
go test ./internal/identity/ -run TestCreateOrgOwned
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/identity` (`CreateOrgOwned` undefined).

- [ ] **2.3 — Implement.** Create `/Users/jacinta/Source/herald/internal/identity/org.go`:

```go
package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ErrAlreadyInOrg is returned when a caller who already belongs to an org tries
// to create or accept into another (the single-org invariant).
var ErrAlreadyInOrg = errors.New("identity: user already belongs to an org")

// CreateOrgOwned validates the slug, creates the org under the tier (default
// hosted), and attaches the calling user as the org's owner. Rejects if the
// caller already belongs to an org.
func (svc *Service) CreateOrgOwned(ctx context.Context, callerID, name, slug, tier string) (store.Org, error) {
	if name == "" {
		return store.Org{}, errors.New("identity: org name required")
	}
	if err := ValidateSlug(slug); err != nil {
		return store.Org{}, err
	}
	if tier == "" {
		tier = store.TierHosted
	}
	if tier != store.TierHosted && tier != store.TierTrusted {
		return store.Org{}, fmt.Errorf("identity: unknown tier %q", tier)
	}
	caller, err := svc.store.GetUser(ctx, callerID)
	if err != nil {
		return store.Org{}, fmt.Errorf("identity.CreateOrgOwned: caller: %w", err)
	}
	if caller.OrgID != "" {
		return store.Org{}, ErrAlreadyInOrg
	}
	org, err := svc.store.CreateOrgWithSlug(ctx, name, slug, tier)
	if err != nil {
		// UNIQUE(tier, slug) collision surfaces here.
		return store.Org{}, fmt.Errorf("identity.CreateOrgOwned: %w", err)
	}
	if err := svc.store.SetUserOrg(ctx, callerID, org.ID, store.RoleOwner); err != nil {
		return store.Org{}, fmt.Errorf("identity.CreateOrgOwned: attach owner: %w", err)
	}
	return org, nil
}

// ValidateSlug enforces a DNS-safe label: lowercase alphanumeric + internal
// hyphens, 1..63 chars, not starting/ending with a hyphen, no double hyphen,
// and not in the reserved list.
func ValidateSlug(slug string) error {
	if slug == "" {
		return errors.New("identity: slug required")
	}
	if len(slug) > 63 {
		return errors.New("identity: slug too long (max 63)")
	}
	if store.ReservedSlugs[slug] {
		return fmt.Errorf("identity: slug %q is reserved", slug)
	}
	prev := byte('-') // disallow leading hyphen by seeding prev as hyphen-ish guard
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
		if !ok {
			return fmt.Errorf("identity: slug has invalid char %q (lowercase alnum + hyphen only)", string(c))
		}
		if c == '-' {
			if i == 0 || i == len(slug)-1 {
				return errors.New("identity: slug must not start or end with a hyphen")
			}
			if prev == '-' {
				return errors.New("identity: slug must not contain a double hyphen")
			}
		}
		prev = c
	}
	return nil
}
```

- [ ] **2.4 — Run, expect PASS:**

```
go test ./internal/identity/ -run TestCreateOrgOwned
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`

- [ ] **2.5 — Add the auth-gating helper + re-gate the handler.** Edit `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`.

Extend the `Identity` interface (add the org methods used by Tasks 2–7 now so the interface is stable):

```go
type Identity interface {
	CreateOrg(ctx context.Context, name string) (store.Org, error)
	CreateOrgOwned(ctx context.Context, callerID, name, slug, tier string) (store.Org, error)
	CreateHuman(ctx context.Context, orgID, displayName string) (store.User, error)
	CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	CreateAgentPending(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	ValidateAgent(ctx context.Context, agentID, validatingHuman string) error
	GrantScope(ctx context.Context, userID, scope, grantedBy string) error
	GetUser(ctx context.Context, id string) (store.User, error)
	GetOrg(ctx context.Context, id string) (store.Org, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
}
```

(`identity.Service` already has `GetOrg` indirectly? No — it does not expose `GetOrg`. Add a passthrough in identity: edit `/Users/jacinta/Source/herald/internal/identity/identity.go` and add:)

```go
// GetOrg returns an org by id.
func (svc *Service) GetOrg(ctx context.Context, id string) (store.Org, error) {
	return svc.store.GetOrg(ctx, id)
}
```

Add the user-token gating helpers to adminapi.go (after `adminOnly`):

```go
// callerIdentity verifies the bearer token and returns the caller's identity
// claims (sub, kind, org, org_role, email_verified). Returns an error suitable
// for a 401.
type callerClaims struct {
	Sub           string
	Kind          string
	Org           string
	OrgRole       string
	EmailVerified bool
	Email         string
}

func (a *API) callerIdentity(r *http.Request) (callerClaims, error) {
	claims, err := a.verifyBearer(r)
	if err != nil {
		return callerClaims{}, err
	}
	c := callerClaims{}
	c.Sub, _ = claims["sub"].(string)
	c.Kind, _ = claims["kind"].(string)
	c.Org, _ = claims["org"].(string)
	c.OrgRole, _ = claims["org_role"].(string)
	c.Email, _ = claims["email"].(string)
	// email_verified may arrive as bool or as a non-empty timestamp string.
	switch v := claims["email_verified"].(type) {
	case bool:
		c.EmailVerified = v
	case string:
		c.EmailVerified = v != ""
	}
	if c.Sub == "" {
		return callerClaims{}, errors.New("token missing sub")
	}
	return c, nil
}

// requireOwner gates an org-scoped endpoint: the path {org} must equal the
// caller's token org, and the caller's role must be owner — RE-CHECKED from the
// stored user record (the token claim is a convenience, not the source of
// truth). Returns the caller's identity on success; writes the error + returns
// ok=false on failure.
func (a *API) requireOwner(w http.ResponseWriter, r *http.Request) (callerClaims, bool) {
	c, err := a.callerIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "valid herald token required")
		return callerClaims{}, false
	}
	pathOrg := r.PathValue("org")
	if c.Org == "" || c.Org != pathOrg {
		writeErr(w, http.StatusForbidden, "token org does not match path org")
		return callerClaims{}, false
	}
	rec, err := a.id.GetUser(r.Context(), c.Sub)
	if err != nil {
		writeErr(w, http.StatusForbidden, "caller not found")
		return callerClaims{}, false
	}
	if rec.OrgID != pathOrg || rec.OrgRole != store.RoleOwner {
		writeErr(w, http.StatusForbidden, "owner role required")
		return callerClaims{}, false
	}
	c.OrgRole = rec.OrgRole // trust the record
	return c, true
}
```

Replace `handleCreateOrg` and its route registration. Change the route in `Handler()`:

```go
	// Org creation: user-token gated (NEX-415). Caller becomes owner.
	mux.HandleFunc("POST /api/orgs", a.handleCreateOrg)
```

Replace the handler body:

```go
func (a *API) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	c, err := a.callerIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "valid herald token required")
		return
	}
	if c.Kind != string(store.KindHuman) {
		writeErr(w, http.StatusForbidden, "only a human may create an org")
		return
	}
	if !c.EmailVerified {
		writeErr(w, http.StatusForbidden, "email not verified")
		return
	}
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Tier string `json:"tier"`
	}
	if !decode(w, r, &body) {
		return
	}
	org, err := a.id.CreateOrgOwned(r.Context(), c.Sub, body.Name, body.Slug, body.Tier)
	if errors.Is(err, identity.ErrAlreadyInOrg) {
		writeErr(w, http.StatusConflict, "caller already belongs to an org")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": org.ID, "name": org.Name, "slug": org.Slug, "tier": org.Tier,
	})
}
```

Add the import for `identity` to adminapi.go's import block:

```go
	"github.com/CarriedWorldUniverse/herald/internal/identity"
```

- [ ] **2.6 — Add an owner-token mint helper for the human-token endpoint.** So a freshly-created owner's *next* token carries `org_role`, update `handleIssueHumanToken` to include `org_role` + `email`/`email_verified` from the record. Edit the claims assembly in `handleIssueHumanToken`:

```go
	scopes, _ := a.id.EffectiveScopes(r.Context(), humanID)
	claims := map[string]any{
		"sub":   human.ID,
		"kind":  string(store.KindHuman),
		"org":   human.OrgID,
		"scope": joinFields(scopes),
	}
	if human.OrgRole != "" {
		claims["org_role"] = human.OrgRole
	}
	if human.CasketFingerprint != "" {
		claims["human_fp"] = human.CasketFingerprint
	}
```

(Path-A note: `human.Email`/`email_verified` are added to the claims by path-A's amended token assembly. For testing org creation in this repo before path-A, tests inject `email_verified` via a directly-signed provider token — see 2.7.)

- [ ] **2.7 — Failing handler test.** Create `/Users/jacinta/Source/herald/internal/adminapi/org_test.go`:

```go
package adminapi_test

import (
	"net/http"
	"testing"

	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// signUserToken signs a herald token directly for a stored user, with the
// org-ownership + email_verified claims. Stands in for the path-A login token
// until path-A lands; lets adminapi tests exercise org endpoints.
func signUserToken(t *testing.T, p *herald.Provider, u store.User, emailVerified bool) string {
	t.Helper()
	claims := map[string]any{
		"sub":            u.ID,
		"kind":           string(u.Kind),
		"org":            u.OrgID,
		"email":          u.DisplayName + "@acme.com",
		"email_verified": emailVerified,
	}
	if u.OrgRole != "" {
		claims["org_role"] = u.OrgRole
	}
	tok, err := p.SignToken(claims)
	if err != nil {
		t.Fatalf("signUserToken: %v", err)
	}
	return tok
}

func TestCreateOrg_ByUserToken(t *testing.T) {
	svc, p, srv := newStack(t)
	ctx := contextBG()

	// An orgless, email-verified human (seeded directly in the store).
	u, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	tok := signUserToken(t, p, u, true)

	resp, body := doJSON(t, "POST", srv.URL+"/api/orgs", tok, map[string]any{
		"name": "Acme Inc", "slug": "acme",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create org: %d %+v", resp.StatusCode, body)
	}
	if body["slug"] != "acme" || body["tier"] != "hosted" {
		t.Fatalf("bad org body: %+v", body)
	}

	// The admin token is NO LONGER accepted for org creation (it's not a user token).
	resp, _ = adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "x", "slug": "x"})
	if resp.StatusCode == http.StatusOK {
		t.Fatal("admin token must not create orgs anymore")
	}
}

func TestCreateOrg_UnverifiedEmailRejected(t *testing.T) {
	svc, p, srv := newStack(t)
	u, _ := storeOf(svc).CreateUser(contextBG(), store.User{Kind: store.KindHuman, DisplayName: "x"})
	tok := signUserToken(t, p, u, false)
	resp, _ := doJSON(t, "POST", srv.URL+"/api/orgs", tok, map[string]any{"name": "x", "slug": "x"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified email org create should be 403, got %d", resp.StatusCode)
	}
}
```

This test needs two small helpers exposed for tests: `storeOf` (to seed users directly) and `contextBG`. Add them to the existing `adminapi_test.go` — but `newStack` returns `*identity.Service`, not the store. Add a test-only accessor instead: store a reference. Simplest: add helpers in a new test file `/Users/jacinta/Source/herald/internal/adminapi/helpers_test.go`:

```go
package adminapi_test

import (
	"context"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func contextBG() context.Context { return context.Background() }

// storeOf returns the store backing a Service. The Service does not expose its
// store, so for tests we instead seed users through the service's CreateHuman +
// then attach orgs through the store opened in newStack. To keep this simple,
// newStack is amended (helpers_test) to stash the store in a package var.
var lastStore store.Store

func storeOf(_ *identity.Service) store.Store { return lastStore }
```

And amend `newStack` in `adminapi_test.go` to stash the store: after `s, err := store.Open(":memory:")` and the `svc := identity.New(s)` line, add `lastStore = s`.

- [ ] **2.8 — Run, expect FAIL:**

```
go test ./internal/adminapi/ -run TestCreateOrg
```
Expected output prefix: a FAIL — either the route still admin-gated, or 401 because the user-token path/claims helper not yet effective. (If 2.5/2.6 are already applied, this should PASS; the ordering here keeps test-first discipline — write 2.7 before re-running.)

- [ ] **2.9 — Make existing golden-path tests use the new contract.** `TestGoldenPath` in `adminapi_test.go` creates the org via the admin token (now invalid). Update its step 1 to seed the first org via the store directly + create the human, OR keep admin org-create only through the bootstrap user path. Minimal fix: replace `TestGoldenPath`'s steps 1–2 with a store-seeded org + human, then continue with the agent bootstrap unchanged:

```go
	// 1+2. Seed an org + a human directly in the store (the admin-token org-create
	// path is gone; org creation is now user-token driven and covered by
	// TestCreateOrg_ByUserToken). The agent-bootstrap flow below is unchanged.
	ctxSeed := context.Background()
	seededOrg, _ := lastStore.CreateOrgWithSlug(ctxSeed, "acme", "acme", "hosted")
	orgID := seededOrg.ID
	seededHuman, _ := lastStore.CreateUser(ctxSeed, store.User{
		OrgID: orgID, OrgRole: store.RoleOwner, Kind: store.KindHuman, DisplayName: "jacinta",
	})
	humanID := seededHuman.ID
```

Delete the now-dead lines in `TestGoldenPath` that asserted the unauthenticated/admin org-create behaviour (the `resp.StatusCode != http.StatusUnauthorized` block and the `adminPost(... "/api/orgs" ...)` block), since `POST /api/orgs` is no longer admin-gated. `TestValidate_OnlyResponsibleHuman` and `TestSelfProvision_*` also call `adminPost(... "/api/orgs" ...)`; update each to seed via `lastStore.CreateOrgWithSlug` + `lastStore.CreateUser` the same way (replace the `_, org := adminPost(...)` + `orgID, _ := org["id"].(string)` pair).

- [ ] **2.10 — Run the package, expect PASS:**

```
go test ./internal/adminapi/
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`

- [ ] **2.11 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` lines for each package; no `FAIL`.

- [ ] **2.12 — Commit:**

```
git commit -am "nex-415: org creation by user token + slug/tier validation, owner attach, single-org invariant

<trailer>"
```

---

# Task 3 — Org domain verification (NEX-416)

**Goal:** `POST /api/orgs/{org}/domain` (owner-gated) issues a TXT challenge plus the DKIM/SPF records to publish; `POST /api/orgs/{org}/domain/verify` re-checks DNS via a pluggable resolver (test-injectable) and sets `org.domain` + `org.domain_verified_at`.

### Pluggable resolver

A `DomainResolver` interface lets tests inject DNS answers; production uses `net.Resolver.LookupTXT`. It lives in `identity` (the domain layer owns the verification rule).

### Steps

- [ ] **3.1 — Failing identity test.** Create `/Users/jacinta/Source/herald/internal/identity/domain_test.go`:

```go
package identity_test

import (
	"context"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// fakeResolver returns canned TXT records keyed by name.
type fakeResolver struct{ txt map[string][]string }

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return f.txt[name], nil
}

func TestDomainVerification(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	u, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, u.ID, "Acme", "acme", "")

	ch, err := svc.BeginDomainVerification(ctx, org.ID, "acme.com")
	if err != nil {
		t.Fatalf("BeginDomainVerification: %v", err)
	}
	if ch.TxtToken == "" || !strings.HasPrefix(ch.RecordName, "_herald-challenge.") {
		t.Fatalf("bad challenge: %+v", ch)
	}

	// Before the TXT is published, verify fails.
	empty := fakeResolver{txt: map[string][]string{}}
	if err := svc.VerifyDomain(ctx, org.ID, "acme.com", empty); err == nil {
		t.Fatal("verify should fail before TXT is published")
	}

	// Publish the TXT, then verify succeeds and sets org.domain.
	res := fakeResolver{txt: map[string][]string{
		ch.RecordName: {ch.TxtToken},
	}}
	if err := svc.VerifyDomain(ctx, org.ID, "acme.com", res); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}
	got, _ := st.GetOrg(ctx, org.ID)
	if got.Domain != "acme.com" || got.DomainVerifiedAt == "" {
		t.Fatalf("domain not recorded: %+v", got)
	}
}
```

- [ ] **3.2 — Run, expect FAIL:**

```
go test ./internal/identity/ -run TestDomainVerification
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/identity` (`BeginDomainVerification` undefined).

- [ ] **3.3 — Implement.** Create `/Users/jacinta/Source/herald/internal/identity/domain.go`:

```go
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// DomainResolver is the DNS lookup seam (test-injectable). Production passes a
// *net.Resolver-backed adapter; tests pass a fake.
type DomainResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DomainChallenge is the public view returned to an owner: what to publish.
type DomainChallenge struct {
	Domain     string
	RecordName string // _herald-challenge.<domain>
	TxtToken   string // the value to publish at RecordName
	DKIM       string // the DKIM record the org must add to send-as the domain
	SPF        string // the SPF record the org must add
}

// challengePrefix is the well-known TXT record name prefix for the proof.
const challengePrefix = "_herald-challenge."

// BeginDomainVerification creates (or refreshes) a TXT challenge for the org's
// domain and returns the records the owner must publish. The org must exist.
func (svc *Service) BeginDomainVerification(ctx context.Context, orgID, domain string) (DomainChallenge, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return DomainChallenge{}, fmt.Errorf("identity: domain required")
	}
	if _, err := svc.store.GetOrg(ctx, orgID); err != nil {
		return DomainChallenge{}, fmt.Errorf("identity.BeginDomainVerification: org: %w", err)
	}
	token, err := randToken(24)
	if err != nil {
		return DomainChallenge{}, err
	}
	if err := svc.store.CreateDomainChallenge(ctx, orgID, domain, token); err != nil {
		return DomainChallenge{}, fmt.Errorf("identity.BeginDomainVerification: %w", err)
	}
	return DomainChallenge{
		Domain:     domain,
		RecordName: challengePrefix + domain,
		TxtToken:   token,
		// The ESP-specific selector is wired by path-A's Notifier/ESP config;
		// these are the records the org publishes so the platform can send-as.
		DKIM: fmt.Sprintf("herald._domainkey.%s  IN TXT  \"v=DKIM1; k=ed25519; p=<published-by-esp>\"", domain),
		SPF:  fmt.Sprintf("%s  IN TXT  \"v=spf1 include:_spf.carriedworld.com ~all\"", domain),
	}, nil
}

// VerifyDomain re-checks DNS: the TXT at _herald-challenge.<domain> must contain
// the stored challenge token. On success it records org.domain + verified_at.
func (svc *Service) VerifyDomain(ctx context.Context, orgID, domain string, res DomainResolver) error {
	domain = normalizeDomain(domain)
	ch, err := svc.store.GetDomainChallenge(ctx, orgID, domain)
	if err != nil {
		return fmt.Errorf("identity.VerifyDomain: challenge: %w", err)
	}
	records, err := res.LookupTXT(ctx, challengePrefix+domain)
	if err != nil {
		return fmt.Errorf("identity.VerifyDomain: dns: %w", err)
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == ch.TxtToken {
			return svc.store.SetOrgDomain(ctx, orgID, domain)
		}
	}
	return fmt.Errorf("identity.VerifyDomain: TXT proof not found at %s", challengePrefix+domain)
}

// normalizeDomain lowercases + trims a domain and strips a leading "@".
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	return strings.TrimPrefix(d, "@")
}

// randToken returns a base64url high-entropy token of n random bytes.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("identity: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
```

Note: this declares `identity.DomainChallenge` distinct from `store.DomainChallenge` (the store record). The store type is persistence; this type is the API view. They coexist (different packages).

- [ ] **3.4 — Run, expect PASS:**

```
go test ./internal/identity/ -run TestDomainVerification
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`

- [ ] **3.5 — Add the production resolver adapter + wire handlers.** Edit `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`.

Extend the `Identity` interface:

```go
	BeginDomainVerification(ctx context.Context, orgID, domain string) (identity.DomainChallenge, error)
	VerifyDomain(ctx context.Context, orgID, domain string, res identity.DomainResolver) error
```

Add a stored default resolver to `API` + `New`, and the routes + handlers. Change `API`:

```go
type API struct {
	id         Identity
	tokens     TokenIssuer
	adminToken string
	resolver   identity.DomainResolver
}
```

Change `New`:

```go
func New(id Identity, tokens TokenIssuer, adminToken string) *API {
	return &API{id: id, tokens: tokens, adminToken: adminToken, resolver: netResolver{}}
}
```

Add the adapter (after `New`):

```go
// netResolver is the production DomainResolver backed by net.DefaultResolver.
type netResolver struct{}

func (netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}
```

Add `"net"` to the import block.

Register routes in `Handler()`:

```go
	mux.HandleFunc("POST /api/orgs/{org}/domain", a.handleBeginDomain)
	mux.HandleFunc("POST /api/orgs/{org}/domain/verify", a.handleVerifyDomain)
```

Add the handlers:

```go
func (a *API) handleBeginDomain(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &body) {
		return
	}
	ch, err := a.id.BeginDomainVerification(r.Context(), c.Org, body.Domain)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":      ch.Domain,
		"record_name": ch.RecordName,
		"txt_value":   ch.TxtToken,
		"dkim":        ch.DKIM,
		"spf":         ch.SPF,
	})
}

func (a *API) handleVerifyDomain(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := a.id.VerifyDomain(r.Context(), c.Org, body.Domain, a.resolver); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": body.Domain, "verified": true})
}
```

- [ ] **3.6 — Failing handler test.** Append to `/Users/jacinta/Source/herald/internal/adminapi/org_test.go`:

```go
func TestDomainEndpoints_OwnerGated(t *testing.T) {
	svc, p, srv := newStack(t)
	ctx := contextBG()
	owner, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	tok := signUserToken(t, p, owner, true)
	resp, body := doJSON(t, "POST", srv.URL+"/api/orgs", tok, map[string]any{"name": "Acme", "slug": "acme"})
	orgID, _ := body["id"].(string)
	if resp.StatusCode != 200 {
		t.Fatalf("org: %d %+v", resp.StatusCode, body)
	}
	// Re-mint the owner token now that they have org + role on the record.
	owner, _ = storeOf(svc).GetUser(ctx, owner.ID)
	tok = signUserToken(t, p, owner, true)

	resp, ch := doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/domain", tok, map[string]any{"domain": "acme.com"})
	if resp.StatusCode != 200 || ch["txt_value"] == "" {
		t.Fatalf("begin domain: %d %+v", resp.StatusCode, ch)
	}

	// A non-owner (orgless) caller is rejected.
	stranger, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "x"})
	stok := signUserToken(t, p, stranger, true)
	resp, _ = doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/domain", stok, map[string]any{"domain": "x.com"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger begin-domain should be 403, got %d", resp.StatusCode)
	}
}
```

- [ ] **3.7 — Run, expect PASS:**

```
go test ./internal/adminapi/ -run TestDomainEndpoints
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`

- [ ] **3.8 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` per package; no `FAIL`.

- [ ] **3.9 — Commit:**

```
git commit -am "nex-416: org domain verification — TXT challenge + DKIM/SPF records, pluggable resolver, set org.domain on verify

<trailer>"
```

---

# Task 4 — Invite links (NEX-417)

**Goal:** `POST/GET/DELETE /api/orgs/{org}/invites` (owner-gated). `policy_type ∈ {domain, email_list}`, `policy_value`, `role` (default member), `expires_at`, `max_uses`, `delivery ∈ {link, email}`. `delivery=email` requires a verified domain (else 409). Return the link `https://<slug>.<tier>.carriedworld.com/invite/<token>` + the raw token.

**Path-A note:** none for creation; `delivery=email` *sending* is Task 6 (the create endpoint here only validates that the domain is verified and stores the row; actual send is layered in Task 6).

### Link shape (spec §11 — pinned)

`https://<slug>.<tier>.carriedworld.com/invite/<token>`. The raw token is also returned for API accept. Built in the identity layer from the org's slug+tier.

### Steps

- [ ] **4.1 — Failing identity test.** Create `/Users/jacinta/Source/herald/internal/identity/invite_test.go`:

```go
package identity_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestCreateInvite(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	u, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, u.ID, "Acme", "acme", "")

	inv, link, err := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID:       org.ID,
		CreatedBy:   u.ID,
		PolicyType:  store.PolicyDomain,
		PolicyValue: "acme.com",
		Delivery:    store.DeliveryLink,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if inv.Token == "" || inv.Role != store.RoleMember {
		t.Fatalf("bad invite: %+v", inv)
	}
	want := "https://acme.hosted.carriedworld.com/invite/" + inv.Token
	if link != want {
		t.Fatalf("link = %q, want %q", link, want)
	}

	// delivery=email without a verified domain -> ErrDomainNotVerified.
	_, _, err = svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: u.ID, PolicyType: store.PolicyDomain,
		PolicyValue: "acme.com", Delivery: store.DeliveryEmail,
	})
	if err != identity.ErrDomainNotVerified {
		t.Fatalf("email delivery without verified domain should be ErrDomainNotVerified, got %v", err)
	}

	// list + revoke roundtrip.
	list, _ := svc.ListInvites(ctx, org.ID)
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
	if err := svc.RevokeInvite(ctx, org.ID, inv.Token); err != nil {
		t.Fatalf("RevokeInvite: %v", err)
	}
}

func TestCreateInvite_BadPolicy(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	u, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, u.ID, "Acme", "acme", "")

	// unknown policy_type.
	if _, _, err := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: u.ID, PolicyType: "nope", PolicyValue: "x",
	}); err == nil {
		t.Fatal("unknown policy_type should be rejected")
	}
	// email_list with a non-JSON value.
	if _, _, err := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: u.ID, PolicyType: store.PolicyEmailList, PolicyValue: "not-json",
	}); err == nil {
		t.Fatal("email_list with non-JSON value should be rejected")
	}
}
```

- [ ] **4.2 — Run, expect FAIL:**

```
go test ./internal/identity/ -run TestCreateInvite
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/identity` (`InviteSpec` undefined).

- [ ] **4.3 — Implement.** Create `/Users/jacinta/Source/herald/internal/identity/invite.go`:

```go
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ErrDomainNotVerified is returned when delivery=email is requested but the org
// has no verified sending domain.
var ErrDomainNotVerified = errors.New("identity: org domain not verified")

// InviteSpec is the input to CreateInvite.
type InviteSpec struct {
	OrgID       string
	CreatedBy   string
	Role        string // default member
	PolicyType  string // domain | email_list
	PolicyValue string // domain string OR JSON array of emails
	Delivery    string // link (default) | email
	ExpiresAt   string // optional RFC3339/SQLite timestamp; "" = none
	MaxUses     int    // 0 = unlimited
}

// CreateInvite validates the spec, persists the invite, and returns the stored
// row plus the accept link (https://<slug>.<tier>.carriedworld.com/invite/<tok>).
func (svc *Service) CreateInvite(ctx context.Context, spec InviteSpec) (store.Invite, string, error) {
	org, err := svc.store.GetOrg(ctx, spec.OrgID)
	if err != nil {
		return store.Invite{}, "", fmt.Errorf("identity.CreateInvite: org: %w", err)
	}
	role := spec.Role
	if role == "" {
		role = store.RoleMember
	}
	delivery := spec.Delivery
	if delivery == "" {
		delivery = store.DeliveryLink
	}
	if delivery != store.DeliveryLink && delivery != store.DeliveryEmail {
		return store.Invite{}, "", fmt.Errorf("identity: unknown delivery %q", delivery)
	}
	if delivery == store.DeliveryEmail && org.DomainVerifiedAt == "" {
		return store.Invite{}, "", ErrDomainNotVerified
	}
	if err := validatePolicy(spec.PolicyType, spec.PolicyValue); err != nil {
		return store.Invite{}, "", err
	}
	token, err := randToken(32)
	if err != nil {
		return store.Invite{}, "", err
	}
	inv, err := svc.store.CreateInvite(ctx, store.Invite{
		Token:       token,
		OrgID:       spec.OrgID,
		Role:        role,
		PolicyType:  spec.PolicyType,
		PolicyValue: spec.PolicyValue,
		Delivery:    delivery,
		ExpiresAt:   spec.ExpiresAt,
		MaxUses:     spec.MaxUses,
		CreatedBy:   spec.CreatedBy,
	})
	if err != nil {
		return store.Invite{}, "", fmt.Errorf("identity.CreateInvite: %w", err)
	}
	return inv, InviteLink(org, inv.Token), nil
}

// InviteLink builds the accept URL for an org's tenant hostname.
func InviteLink(org store.Org, token string) string {
	return fmt.Sprintf("https://%s.%s.carriedworld.com/invite/%s", org.Slug, org.Tier, token)
}

// ListInvites returns the org's invites.
func (svc *Service) ListInvites(ctx context.Context, orgID string) ([]store.Invite, error) {
	return svc.store.ListInvites(ctx, orgID)
}

// RevokeInvite soft-deletes an invite within an org.
func (svc *Service) RevokeInvite(ctx context.Context, orgID, token string) error {
	return svc.store.RevokeInvite(ctx, orgID, token)
}

// validatePolicy checks policy_type/value coherence.
func validatePolicy(policyType, policyValue string) error {
	switch policyType {
	case store.PolicyDomain:
		d := normalizeDomain(policyValue)
		if d == "" || !strings.Contains(d, ".") {
			return fmt.Errorf("identity: domain policy_value must be a domain, got %q", policyValue)
		}
		return nil
	case store.PolicyEmailList:
		var emails []string
		if err := json.Unmarshal([]byte(policyValue), &emails); err != nil {
			return fmt.Errorf("identity: email_list policy_value must be a JSON array of emails: %w", err)
		}
		if len(emails) == 0 {
			return errors.New("identity: email_list policy_value must be non-empty")
		}
		return nil
	default:
		return fmt.Errorf("identity: unknown policy_type %q", policyType)
	}
}
```

- [ ] **4.4 — Run, expect PASS:**

```
go test ./internal/identity/ -run TestCreateInvite
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`

- [ ] **4.5 — Wire handlers.** Edit `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`.

Extend `Identity`:

```go
	CreateInvite(ctx context.Context, spec identity.InviteSpec) (store.Invite, string, error)
	ListInvites(ctx context.Context, orgID string) ([]store.Invite, error)
	RevokeInvite(ctx context.Context, orgID, token string) error
```

Register routes in `Handler()`:

```go
	mux.HandleFunc("POST /api/orgs/{org}/invites", a.handleCreateInvite)
	mux.HandleFunc("GET /api/orgs/{org}/invites", a.handleListInvites)
	mux.HandleFunc("DELETE /api/orgs/{org}/invites/{token}", a.handleRevokeInvite)
```

Add handlers:

```go
func (a *API) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	var body struct {
		PolicyType  string `json:"policy_type"`
		PolicyValue string `json:"policy_value"`
		Role        string `json:"role"`
		ExpiresAt   string `json:"expires_at"`
		MaxUses     int    `json:"max_uses"`
		Delivery    string `json:"delivery"`
	}
	if !decode(w, r, &body) {
		return
	}
	inv, link, err := a.id.CreateInvite(r.Context(), identity.InviteSpec{
		OrgID:       c.Org,
		CreatedBy:   c.Sub,
		Role:        body.Role,
		PolicyType:  body.PolicyType,
		PolicyValue: body.PolicyValue,
		Delivery:    body.Delivery,
		ExpiresAt:   body.ExpiresAt,
		MaxUses:     body.MaxUses,
	})
	if err == identity.ErrDomainNotVerified {
		writeErr(w, http.StatusConflict, "delivery=email requires a verified org domain")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     inv.Token,
		"link":      link,
		"role":      inv.Role,
		"policy":    map[string]any{"type": inv.PolicyType, "value": inv.PolicyValue},
		"delivery":  inv.Delivery,
		"max_uses":  inv.MaxUses,
		"expires_at": inv.ExpiresAt,
	})
}

func (a *API) handleListInvites(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	invites, err := a.id.ListInvites(r.Context(), c.Org)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out := make([]map[string]any, 0, len(invites))
	for _, inv := range invites {
		live := inv.RevokedAt == ""
		out = append(out, map[string]any{
			"token_prefix": tokenPrefix(inv.Token),
			"role":         inv.Role,
			"policy_type":  inv.PolicyType,
			"policy_value": inv.PolicyValue,
			"delivery":     inv.Delivery,
			"max_uses":     inv.MaxUses,
			"uses":         inv.Uses,
			"expires_at":   inv.ExpiresAt,
			"live":         live,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

func (a *API) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	token := r.PathValue("token")
	if err := a.id.RevokeInvite(r.Context(), c.Org, token); err != nil {
		writeErr(w, http.StatusNotFound, "invite not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token_prefix": tokenPrefix(token), "revoked": true})
}

// tokenPrefix returns a non-secret prefix for listing (first 8 chars).
func tokenPrefix(tok string) string {
	if len(tok) <= 8 {
		return tok
	}
	return tok[:8] + "…"
}
```

- [ ] **4.6 — Failing handler test.** Append to `/Users/jacinta/Source/herald/internal/adminapi/org_test.go`:

```go
func TestInviteEndpoints(t *testing.T) {
	svc, p, srv := newStack(t)
	ctx := contextBG()
	owner, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	tok := signUserToken(t, p, owner, true)
	_, body := doJSON(t, "POST", srv.URL+"/api/orgs", tok, map[string]any{"name": "Acme", "slug": "acme"})
	orgID, _ := body["id"].(string)
	owner, _ = storeOf(svc).GetUser(ctx, owner.ID)
	tok = signUserToken(t, p, owner, true)

	resp, inv := doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/invites", tok, map[string]any{
		"policy_type": "domain", "policy_value": "acme.com",
	})
	if resp.StatusCode != 200 || inv["token"] == "" {
		t.Fatalf("create invite: %d %+v", resp.StatusCode, inv)
	}
	if inv["link"] != "https://acme.hosted.carriedworld.com/invite/"+inv["token"].(string) {
		t.Fatalf("bad link: %+v", inv["link"])
	}

	// delivery=email without a verified domain -> 409.
	resp, _ = doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/invites", tok, map[string]any{
		"policy_type": "domain", "policy_value": "acme.com", "delivery": "email",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("email delivery without domain should be 409, got %d", resp.StatusCode)
	}

	// list shows the one live invite by prefix (no full secret).
	resp, list := doJSON(t, "GET", srv.URL+"/api/orgs/"+orgID+"/invites", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %+v", resp.StatusCode, list)
	}
	arr, _ := list["invites"].([]any)
	if len(arr) != 1 {
		t.Fatalf("expected 1 invite, got %+v", list)
	}

	// revoke.
	resp, _ = doJSON(t, "DELETE", srv.URL+"/api/orgs/"+orgID+"/invites/"+inv["token"].(string), tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
}
```

- [ ] **4.7 — Run, expect PASS:**

```
go test ./internal/adminapi/ -run TestInviteEndpoints
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`

- [ ] **4.8 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` per package; no `FAIL`.

- [ ] **4.9 — Commit:**

```
git commit -am "nex-417: org invite links — create/list/revoke (owner-gated), domain|email_list policy, delivery link|email, tenant accept link

<trailer>"
```

---

# Task 5 — Accept invite (NEX-418)

**Goal:** `POST /api/invites/{token}/accept` by an authenticated, email-verified user. Check live + not-exhausted + verified-email satisfies policy (domain-suffix or allowlist). Set `org_id` + `org_role`; increment uses. Reject if already in an org.

**Path-A note:** The accepting user's verified email is read from the **token claims** (`email` + `email_verified`). Until path-A wires those into the login token, the test signs a token directly with the claims (as in Task 2). The policy match uses the claim email, never client body input.

### Steps

- [ ] **5.1 — Failing identity test.** Create `/Users/jacinta/Source/herald/internal/identity/accept_test.go`:

```go
package identity_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestAcceptInvite_DomainPolicy(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	owner, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, owner.ID, "Acme", "acme", "")
	inv, _, _ := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: owner.ID, PolicyType: store.PolicyDomain, PolicyValue: "acme.com",
	})

	// An orgless user with a matching verified email.
	joiner, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "bob"})

	if err := svc.AcceptInvite(ctx, inv.Token, joiner.ID, "bob@acme.com", true); err != nil {
		t.Fatalf("AcceptInvite: %v", err)
	}
	got, _ := st.GetUser(ctx, joiner.ID)
	if got.OrgID != org.ID || got.OrgRole != store.RoleMember {
		t.Fatalf("joiner not attached as member: %+v", got)
	}
	// uses incremented.
	after, _ := st.GetInvite(ctx, inv.Token)
	if after.Uses != 1 {
		t.Fatalf("uses = %d, want 1", after.Uses)
	}

	// Non-matching domain rejected.
	other, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "eve"})
	if err := svc.AcceptInvite(ctx, inv.Token, other.ID, "eve@evil.com", true); err != identity.ErrPolicyMismatch {
		t.Fatalf("non-matching domain should be ErrPolicyMismatch, got %v", err)
	}

	// Unverified email rejected.
	u2, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "u2"})
	if err := svc.AcceptInvite(ctx, inv.Token, u2.ID, "u2@acme.com", false); err != identity.ErrEmailNotVerified {
		t.Fatalf("unverified email should be ErrEmailNotVerified, got %v", err)
	}

	// Already-in-an-org user rejected (the owner).
	if err := svc.AcceptInvite(ctx, inv.Token, owner.ID, "jacinta@acme.com", true); err != identity.ErrAlreadyInOrg {
		t.Fatalf("already-in-org accept should be ErrAlreadyInOrg, got %v", err)
	}
}

func TestAcceptInvite_EmailListAndExhaustion(t *testing.T) {
	svc, st := newSvc(t)
	ctx := context.Background()
	owner, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, owner.ID, "Acme", "acme", "")
	inv, _, _ := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: owner.ID, PolicyType: store.PolicyEmailList,
		PolicyValue: `["bob@acme.com"]`, MaxUses: 1,
	})

	bob, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "bob"})
	if err := svc.AcceptInvite(ctx, inv.Token, bob.ID, "BOB@acme.com", true); err != nil {
		t.Fatalf("accept (case-insensitive): %v", err)
	}
	// Exhausted (max_uses=1).
	carol, _ := st.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "carol"})
	if err := svc.AcceptInvite(ctx, inv.Token, carol.ID, "bob@acme.com", true); err != identity.ErrInviteUnavailable {
		t.Fatalf("exhausted invite should be ErrInviteUnavailable, got %v", err)
	}
}
```

- [ ] **5.2 — Run, expect FAIL:**

```
go test ./internal/identity/ -run TestAcceptInvite
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/identity` (`AcceptInvite` undefined).

- [ ] **5.3 — Implement.** Create `/Users/jacinta/Source/herald/internal/identity/accept.go`:

```go
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

var (
	// ErrInviteUnavailable: invite missing, expired, exhausted, or revoked.
	ErrInviteUnavailable = errors.New("identity: invite unavailable")
	// ErrPolicyMismatch: the user's verified email does not satisfy the policy.
	ErrPolicyMismatch = errors.New("identity: email does not satisfy invite policy")
	// ErrEmailNotVerified: the accepting user's email is not verified.
	ErrEmailNotVerified = errors.New("identity: email not verified")
)

// AcceptInvite attaches an authenticated, email-verified user to the invite's
// org with the invite's role. The email + emailVerified MUST come from the
// caller's verified token (not client body). Increments uses on success.
func (svc *Service) AcceptInvite(ctx context.Context, token, userID, email string, emailVerified bool) error {
	if !emailVerified {
		return ErrEmailNotVerified
	}
	inv, err := svc.store.GetInvite(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return ErrInviteUnavailable
	}
	if err != nil {
		return fmt.Errorf("identity.AcceptInvite: %w", err)
	}
	if !inviteLive(inv) {
		return ErrInviteUnavailable
	}
	user, err := svc.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("identity.AcceptInvite: user: %w", err)
	}
	if user.OrgID != "" {
		return ErrAlreadyInOrg
	}
	if !emailSatisfiesPolicy(email, inv.PolicyType, inv.PolicyValue) {
		return ErrPolicyMismatch
	}
	if err := svc.store.SetUserOrg(ctx, userID, inv.OrgID, inv.Role); err != nil {
		return fmt.Errorf("identity.AcceptInvite: attach: %w", err)
	}
	if err := svc.store.IncrementInviteUses(ctx, token); err != nil {
		return fmt.Errorf("identity.AcceptInvite: increment uses: %w", err)
	}
	return nil
}

// inviteLive reports whether the invite may still be accepted.
func inviteLive(inv store.Invite) bool {
	if inv.RevokedAt != "" {
		return false
	}
	if inv.MaxUses > 0 && inv.Uses >= inv.MaxUses {
		return false
	}
	if inv.ExpiresAt != "" {
		if exp, err := time.Parse("2006-01-02 15:04:05", inv.ExpiresAt); err == nil {
			if time.Now().UTC().After(exp) {
				return false
			}
		} else if exp, err := time.Parse(time.RFC3339, inv.ExpiresAt); err == nil {
			if time.Now().After(exp) {
				return false
			}
		}
	}
	return true
}

// emailSatisfiesPolicy: domain -> the email's domain equals policy_value
// (case-insensitive, exact — subdomains do NOT match, per spec §11); email_list
// -> the lowercased email is in the JSON allowlist.
func emailSatisfiesPolicy(email, policyType, policyValue string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	switch policyType {
	case store.PolicyDomain:
		return domain == normalizeDomain(policyValue)
	case store.PolicyEmailList:
		var emails []string
		if err := json.Unmarshal([]byte(policyValue), &emails); err != nil {
			return false
		}
		for _, e := range emails {
			if strings.ToLower(strings.TrimSpace(e)) == email {
				return true
			}
		}
		return false
	}
	return false
}
```

- [ ] **5.4 — Run, expect PASS:**

```
go test ./internal/identity/ -run TestAcceptInvite
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`

- [ ] **5.5 — Wire the handler.** Edit `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`.

Extend `Identity`:

```go
	AcceptInvite(ctx context.Context, token, userID, email string, emailVerified bool) error
```

Register route in `Handler()` (note: NOT under `{org}` — keyed only by token):

```go
	mux.HandleFunc("POST /api/invites/{token}/accept", a.handleAcceptInvite)
```

Add handler:

```go
func (a *API) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	c, err := a.callerIdentity(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "valid herald token required")
		return
	}
	if c.Kind != string(store.KindHuman) {
		writeErr(w, http.StatusForbidden, "only a human may accept an invite")
		return
	}
	token := r.PathValue("token")
	err = a.id.AcceptInvite(r.Context(), token, c.Sub, c.Email, c.EmailVerified)
	switch {
	case err == identity.ErrAlreadyInOrg:
		writeErr(w, http.StatusConflict, "caller already belongs to an org")
		return
	case err == identity.ErrEmailNotVerified:
		writeErr(w, http.StatusForbidden, "email not verified")
		return
	case err == identity.ErrPolicyMismatch:
		writeErr(w, http.StatusForbidden, "email does not satisfy the invite policy")
		return
	case err == identity.ErrInviteUnavailable:
		writeErr(w, http.StatusNotFound, "invite not available")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accepted": true})
}
```

- [ ] **5.6 — Failing handler test (full loop).** Append to `/Users/jacinta/Source/herald/internal/adminapi/org_test.go`:

```go
func TestAcceptInvite_FullLoop(t *testing.T) {
	svc, p, srv := newStack(t)
	ctx := contextBG()

	// Owner creates org + a domain invite.
	owner, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	otok := signUserToken(t, p, owner, true)
	_, ob := doJSON(t, "POST", srv.URL+"/api/orgs", otok, map[string]any{"name": "Acme", "slug": "acme"})
	orgID, _ := ob["id"].(string)
	owner, _ = storeOf(svc).GetUser(ctx, owner.ID)
	otok = signUserToken(t, p, owner, true)
	_, inv := doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/invites", otok, map[string]any{
		"policy_type": "domain", "policy_value": "acme.com",
	})
	token, _ := inv["token"].(string)

	// A second orgless user with a matching verified email accepts.
	joiner, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "bob"})
	jtok := signUserToken(t, p, joiner, true) // signUserToken sets email = bob@acme.com
	resp, body := doJSON(t, "POST", srv.URL+"/api/invites/"+token+"/accept", jtok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("accept: %d %+v", resp.StatusCode, body)
	}
	got, _ := storeOf(svc).GetUser(ctx, joiner.ID)
	if got.OrgID != orgID || got.OrgRole != store.RoleMember {
		t.Fatalf("joiner not a member: %+v", got)
	}
}
```

(Note: `signUserToken` sets `email` to `<DisplayName>@acme.com`, so display name `bob` yields `bob@acme.com`, matching the domain policy.)

- [ ] **5.7 — Run, expect PASS:**

```
go test ./internal/adminapi/ -run TestAcceptInvite
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`

- [ ] **5.8 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` per package; no `FAIL`.

- [ ] **5.9 — Commit:**

```
git commit -am "nex-418: accept invite — verified-email policy match (domain/allowlist), attach as member, increment uses, single-org guard

<trailer>"
```

---

# Task 6 — Branded email invites (NEX-419)

**Goal:** When `delivery=email`, send the invite via the path-A Notifier using the org's verified domain as the sending identity.

**Path-A dependency (handled via local stub — option (b)):** The canonical `Notifier` lands in path-A. This task declares a **minimal local `Notifier` interface in herald** (in `identity`) with a no-op/capture default, so org-ownership compiles + tests pass before path-A's ESP backend exists. When path-A lands its `Notifier`, replace this local interface with the path-A import — the call site (`svc.notifier.Send`) is unchanged. The local interface is intentionally a structural superset-free minimum: `Send(ctx, Message) error`.

### Steps

- [ ] **6.1 — Failing identity test.** Create `/Users/jacinta/Source/herald/internal/identity/notify_test.go`:

```go
package identity_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// captureNotifier records the last message sent.
type captureNotifier struct{ last identity.Message }

func (c *captureNotifier) Send(_ context.Context, m identity.Message) error {
	c.last = m
	return nil
}

func TestCreateInvite_EmailDeliverySends(t *testing.T) {
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cap := &captureNotifier{}
	svc := identity.New(s, identity.WithNotifier(cap))
	ctx := context.Background()

	owner, _ := s.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	org, _ := svc.CreateOrgOwned(ctx, owner.ID, "Acme", "acme", "")
	// Verify the domain so email delivery is allowed.
	if err := s.SetOrgDomain(ctx, org.ID, "acme.com"); err != nil {
		t.Fatalf("SetOrgDomain: %v", err)
	}

	inv, _, err := svc.CreateInvite(ctx, identity.InviteSpec{
		OrgID: org.ID, CreatedBy: owner.ID, PolicyType: store.PolicyDomain,
		PolicyValue: "acme.com", Delivery: store.DeliveryEmail,
		Recipients: []string{"bob@acme.com"},
	})
	if err != nil {
		t.Fatalf("CreateInvite email: %v", err)
	}
	if cap.last.To != "bob@acme.com" {
		t.Fatalf("notifier not invoked / wrong recipient: %+v", cap.last)
	}
	if cap.last.FromDomain != "acme.com" {
		t.Fatalf("send-as domain = %q, want acme.com", cap.last.FromDomain)
	}
	if cap.last.Purpose != identity.PurposeOrgInvite {
		t.Fatalf("purpose = %q", cap.last.Purpose)
	}
	if want := "https://acme.hosted.carriedworld.com/invite/" + inv.Token; cap.last.Body == "" || !contains(cap.last.Body, want) {
		t.Fatalf("body missing link %q: %q", want, cap.last.Body)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **6.2 — Run, expect FAIL:**

```
go test ./internal/identity/ -run TestCreateInvite_EmailDeliverySends
```
Expected output prefix: `# github.com/CarriedWorldUniverse/herald/internal/identity` (`WithNotifier`, `Message`, `Recipients` undefined; `identity.New` arity changed).

- [ ] **6.3 — Implement the Notifier seam.** Create `/Users/jacinta/Source/herald/internal/identity/notify.go`:

```go
package identity

import "context"

// Notifier is herald's outbound-message seam (LOCAL STUB — see plan Task 6).
// path-A owns the canonical Notifier + ESP backend; this minimal interface lets
// org-ownership compile + test before that lands. When path-A ships, replace
// this declaration with an import of the path-A Notifier; the call site is
// unchanged.
type Notifier interface {
	Send(ctx context.Context, msg Message) error
}

// Purpose tags the kind of message (for templating + audit downstream).
type Purpose string

const (
	PurposeOrgInvite Purpose = "org_invite"
)

// Message is one outbound notification. FromDomain is the sending identity: the
// org's verified domain for org invites (so the recipient sees mail from their
// own company), the platform domain for account-level mail.
type Message struct {
	To         string
	FromDomain string
	Purpose    Purpose
	Subject    string
	Body       string
}

// noopNotifier is the default when none is configured: sending is a silent
// no-op. (A real deployment wires the path-A ESP-backed Notifier.)
type noopNotifier struct{}

func (noopNotifier) Send(context.Context, Message) error { return nil }
```

- [ ] **6.4 — Make `identity.New` accept options + hold a Notifier.** Edit `/Users/jacinta/Source/herald/internal/identity/identity.go`.

Change the `Service` struct + `New`:

```go
// Service is herald's identity domain logic over a store.Store.
type Service struct {
	store    store.Store
	notifier Notifier
}

// Option configures a Service.
type Option func(*Service)

// WithNotifier sets the outbound notifier (org invite emails). Defaults to a
// no-op when unset.
func WithNotifier(n Notifier) Option {
	return func(s *Service) { s.notifier = n }
}

// New constructs a Service.
func New(s store.Store, opts ...Option) *Service {
	svc := &Service{store: s, notifier: noopNotifier{}}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}
```

(Existing callers `identity.New(s)` and `identity.New(st)` remain valid — variadic opts default to no-op.)

- [ ] **6.5 — Send on email delivery.** Edit `/Users/jacinta/Source/herald/internal/identity/invite.go`.

Add `Recipients` to `InviteSpec`:

```go
type InviteSpec struct {
	OrgID       string
	CreatedBy   string
	Role        string
	PolicyType  string
	PolicyValue string
	Delivery    string
	ExpiresAt   string
	MaxUses     int
	Recipients  []string // delivery=email: addresses to send the branded invite to
}
```

At the end of `CreateInvite`, before `return inv, InviteLink(org, inv.Token), nil`, add the send:

```go
	link := InviteLink(org, inv.Token)
	if delivery == store.DeliveryEmail {
		for _, to := range spec.Recipients {
			if !emailSatisfiesPolicy(to, spec.PolicyType, spec.PolicyValue) {
				return store.Invite{}, "", fmt.Errorf("identity: recipient %q does not satisfy the invite policy", to)
			}
			msg := Message{
				To:         strings.ToLower(strings.TrimSpace(to)),
				FromDomain: org.Domain,
				Purpose:    PurposeOrgInvite,
				Subject:    fmt.Sprintf("You're invited to %s", org.Name),
				Body:       fmt.Sprintf("You've been invited to join %s. Accept here: %s", org.Name, link),
			}
			if err := svc.notifier.Send(ctx, msg); err != nil {
				return store.Invite{}, "", fmt.Errorf("identity.CreateInvite: send: %w", err)
			}
		}
	}
	return inv, link, nil
```

(Remove the old final `return inv, InviteLink(org, inv.Token), nil` line — the new block ends the function.)

- [ ] **6.6 — Run, expect PASS:**

```
go test ./internal/identity/ -run TestCreateInvite
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/identity`

- [ ] **6.7 — Plumb `Recipients` through the handler.** Edit `handleCreateInvite` in `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`: add `Emails []string \`json:"emails"\`` to the request body struct and pass `Recipients: body.Emails` into the `identity.InviteSpec`. Full updated decode struct + spec:

```go
	var body struct {
		PolicyType  string   `json:"policy_type"`
		PolicyValue string   `json:"policy_value"`
		Role        string   `json:"role"`
		ExpiresAt   string   `json:"expires_at"`
		MaxUses     int      `json:"max_uses"`
		Delivery    string   `json:"delivery"`
		Emails      []string `json:"emails"`
	}
	if !decode(w, r, &body) {
		return
	}
	inv, link, err := a.id.CreateInvite(r.Context(), identity.InviteSpec{
		OrgID:       c.Org,
		CreatedBy:   c.Sub,
		Role:        body.Role,
		PolicyType:  body.PolicyType,
		PolicyValue: body.PolicyValue,
		Delivery:    body.Delivery,
		ExpiresAt:   body.ExpiresAt,
		MaxUses:     body.MaxUses,
		Recipients:  body.Emails,
	})
```

- [ ] **6.8 — Optionally wire a real Notifier in main (left as no-op until path-A).** Edit `/Users/jacinta/Source/herald/cmd/herald/main.go`: the `idsvc := identity.New(st)` line stays unchanged (no-op notifier) and gains a comment:

```go
	// NOTE (NEX-419): the no-op Notifier is the default. When the path-A
	// ESP-backed Notifier lands, wire it here: identity.New(st, identity.WithNotifier(esp)).
	idsvc := identity.New(st)
```

- [ ] **6.9 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` per package; no `FAIL`.

- [ ] **6.10 — Commit:**

```
git commit -am "nex-419: branded email invites — local Notifier seam (no-op default), send-as org verified domain on delivery=email

<trailer>"
```

---

# Task 7 — Re-gate provisioning + org_role claim + bootstrap-only admin token (NEX-420)

**Goal:** `POST /api/orgs/{org}/agents` owner-gated (token org=={org} + org_role==owner, re-checked from the record). Add `org_role` to issued token claims (agent grant + human token). Shrink `HERALD_ADMIN_TOKEN` to a bootstrap `POST /api/users` (seed first user) only.

### Steps

- [ ] **7.1 — Failing handler test.** Append to `/Users/jacinta/Source/herald/internal/adminapi/org_test.go`:

```go
import "encoding/base64"
import casket "github.com/CarriedWorldUniverse/casket-go"

func TestProvisionAgent_OwnerGated(t *testing.T) {
	svc, p, srv := newStack(t)
	ctx := contextBG()

	// Owner creates an org via their user token.
	owner, _ := storeOf(svc).CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: "jacinta"})
	otok := signUserToken(t, p, owner, true)
	_, ob := doJSON(t, "POST", srv.URL+"/api/orgs", otok, map[string]any{"name": "Acme", "slug": "acme"})
	orgID, _ := ob["id"].(string)
	owner, _ = storeOf(svc).GetUser(ctx, owner.ID)
	otok = signUserToken(t, p, owner, true) // now carries org + org_role=owner

	// Owner provisions an agent under themselves — succeeds.
	_, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	resp, ab := doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/agents", otok, map[string]any{
		"display_name":      "anvil",
		"responsible_human": owner.ID,
		"casket_pubkey":     base64.StdEncoding.EncodeToString(pub),
		"scopes":            []string{"repo:read"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("owner provision: %d %+v", resp.StatusCode, ab)
	}

	// The admin token must NOT provision anymore.
	resp, _ = adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", map[string]any{
		"display_name": "x", "responsible_human": owner.ID,
		"casket_pubkey": base64.StdEncoding.EncodeToString(pub),
	})
	if resp.StatusCode == 200 {
		t.Fatal("admin token must not provision agents anymore")
	}

	// A member (not owner) cannot provision.
	member, _ := storeOf(svc).CreateUser(ctx, store.User{
		OrgID: orgID, OrgRole: store.RoleMember, Kind: store.KindHuman, DisplayName: "bob",
	})
	mtok := signUserToken(t, p, member, true)
	resp, _ = doJSON(t, "POST", srv.URL+"/api/orgs/"+orgID+"/agents", mtok, map[string]any{
		"display_name": "x", "responsible_human": member.ID,
		"casket_pubkey": base64.StdEncoding.EncodeToString(pub),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("member provision should be 403, got %d", resp.StatusCode)
	}
}

func TestBootstrapCreateUser(t *testing.T) {
	_, _, srv := newStack(t)
	// Admin token seeds the first user (orgless).
	resp, body := adminPost(t, srv.URL+"/api/users", map[string]any{"display_name": "first"})
	if resp.StatusCode != 200 || body["id"] == "" {
		t.Fatalf("bootstrap create user: %d %+v", resp.StatusCode, body)
	}
	// Without the admin token it is rejected.
	resp, _ = doJSON(t, "POST", srv.URL+"/api/users", "", map[string]any{"display_name": "x"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("create user without admin token should be 401, got %d", resp.StatusCode)
	}
}
```

(`base64`/`casket` are already imported in `adminapi_test.go`; if Go reports a duplicate import when adding the `import` lines above, fold these into that file's existing import block instead of re-importing. Keep the test functions, drop the redundant `import` lines.)

- [ ] **7.2 — Run, expect FAIL:**

```
go test ./internal/adminapi/ -run 'TestProvisionAgent_OwnerGated|TestBootstrapCreateUser'
```
Expected output prefix: FAIL — `/api/orgs/{org}/agents` still admin-gated, `/api/users` route missing.

- [ ] **7.3 — Re-gate agent provisioning + add the bootstrap user endpoint.** Edit `/Users/jacinta/Source/herald/internal/adminapi/adminapi.go`.

In `Handler()`, change the agent-create route to use a new owner-gated handler, and add `POST /api/users` (admin-gated bootstrap). The bootstrap human/agent routes that used `adminOnly` for org-scoped humans are removed from the normal flow; keep only the bootstrap-user seed:

```go
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	// Bootstrap (static admin token): seed the FIRST user only. Everything else
	// flows through the user->org model.
	mux.HandleFunc("POST /api/users", a.adminOnly(a.handleBootstrapUser))
	// Org creation: user-token gated (NEX-415).
	mux.HandleFunc("POST /api/orgs", a.handleCreateOrg)
	// Org domain verification (NEX-416, owner-gated).
	mux.HandleFunc("POST /api/orgs/{org}/domain", a.handleBeginDomain)
	mux.HandleFunc("POST /api/orgs/{org}/domain/verify", a.handleVerifyDomain)
	// Invites (NEX-417, owner-gated).
	mux.HandleFunc("POST /api/orgs/{org}/invites", a.handleCreateInvite)
	mux.HandleFunc("GET /api/orgs/{org}/invites", a.handleListInvites)
	mux.HandleFunc("DELETE /api/orgs/{org}/invites/{token}", a.handleRevokeInvite)
	// Accept an invite (NEX-418, authenticated + email-verified user).
	mux.HandleFunc("POST /api/invites/{token}/accept", a.handleAcceptInvite)
	// Provision an agent within an org (NEX-420, owner-gated; was admin-gated).
	mux.HandleFunc("POST /api/orgs/{org}/agents", a.handleOrgCreateAgent)
	// MVP human "login" stand-in: admin mints a human token (still admin-gated;
	// path-A replaces this with a real login).
	mux.HandleFunc("POST /api/humans/{id}/token", a.adminOnly(a.handleIssueHumanToken))
	// Self-provision tool (herald token, agent:create scope) — creates PENDING.
	mux.HandleFunc("POST /api/agents", a.handleSelfProvisionAgent)
	// Human validates a pending agent (human token; must be the responsible human).
	mux.HandleFunc("POST /api/agents/{id}/validate", a.handleValidateAgent)
	return mux
}
```

Add `handleBootstrapUser` (admin-gated, seeds an orgless human) — uses `CreateUser` via a new identity passthrough. First add the identity passthrough in `/Users/jacinta/Source/herald/internal/identity/identity.go`:

```go
// CreateBootstrapUser seeds an orgless human (deploy-time bootstrap only). The
// returned user has no org; they create or join one via the user->org flow.
func (svc *Service) CreateBootstrapUser(ctx context.Context, displayName string) (store.User, error) {
	if displayName == "" {
		return store.User{}, errors.New("identity: display name required")
	}
	return svc.store.CreateUser(ctx, store.User{Kind: store.KindHuman, DisplayName: displayName})
}
```

Add it to the adminapi `Identity` interface:

```go
	CreateBootstrapUser(ctx context.Context, displayName string) (store.User, error)
```

Add the handler:

```go
func (a *API) handleBootstrapUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if !decode(w, r, &body) {
		return
	}
	u, err := a.id.CreateBootstrapUser(r.Context(), body.DisplayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": u.ID, "display_name": u.DisplayName})
}
```

Add the owner-gated agent-create handler (replaces the admin-gated `handleAdminCreateAgent` path):

```go
// handleOrgCreateAgent provisions an agent within an org. Owner-gated: the
// caller's token org must equal {org} and their role (re-checked from the
// record) must be owner. The responsible_human must be a user in the same org
// (enforced by identity.CreateAgent).
func (a *API) handleOrgCreateAgent(w http.ResponseWriter, r *http.Request) {
	c, ok := a.requireOwner(w, r)
	if !ok {
		return
	}
	var body agentBody
	if !decode(w, r, &body) {
		return
	}
	responsibleHuman := body.ResponsibleHuman
	if responsibleHuman == "" {
		responsibleHuman = c.Sub // default to the owner
	}
	// Org-provisioned agents are created ACTIVE (an owner is human-in-the-loop).
	a.createAgent(w, r.Context(), c.Org, responsibleHuman, body, false)
}
```

`handleAdminCreateAgent` and `handleCreateHuman` are no longer routed. Leave the functions in place only if other tests reference them; the golden-path tests were already migrated in Task 2 to seed via the store, so delete `handleCreateHuman` and `handleAdminCreateAgent` and the now-unused `CreateHuman`/`CreateOrg` entries from the `Identity` interface IF nothing references them. (Run `go vet ./...` to confirm; if `CreateOrg`/`CreateHuman` are still in the interface but unused by adminapi, they may stay — they remain on `identity.Service`. Removing them from the interface is optional cleanup; keeping them is harmless. Do NOT remove them from `identity.Service`.)

- [ ] **7.4 — Add `org_role` to the agent-grant token claims.** Edit `/Users/jacinta/Source/herald/internal/oidc/agent_grant.go` — in `issue`, after assembling `out`, add the agent's org_role (agents inherit no role by default, but the claim is present + consistent). Since agents have `OrgRole == ""`, only set it when non-empty:

```go
	out := map[string]any{
		"sub":      agent.ID,
		"kind":     string(store.KindAgent),
		"org":      agent.OrgID,
		"scope":    strings.Join(scopes, " "),
		"agent_fp": agent.CasketFingerprint,
	}
	if agent.OrgRole != "" {
		out["org_role"] = agent.OrgRole
	}
```

(The human-token path `handleIssueHumanToken` already added `org_role` in Task 2.6.)

- [ ] **7.5 — Run, expect PASS:**

```
go test ./internal/adminapi/ -run 'TestProvisionAgent_OwnerGated|TestBootstrapCreateUser'
```
Expected output prefix: `ok  	github.com/CarriedWorldUniverse/herald/internal/adminapi`

- [ ] **7.6 — Fix remaining tests that used removed routes.** `TestGoldenPath` and `TestValidate_OnlyResponsibleHuman` and `TestSelfProvision_*` were migrated in Task 2.9 to seed orgs/humans via the store. The bootstrap agent in `TestGoldenPath` was created via `adminPost(... "/api/orgs/"+orgID+"/agents" ...)` — that route is now owner-gated, not admin-gated. Replace that bootstrap-agent creation with a direct identity-service call through the store-backed service. `TestGoldenPath` has the `svc` handle (`svc, _, srv := newStack(t)`), so create the bootstrap agent directly:

```go
	// 3. Seed the bootstrap agent directly via the identity service (the
	//    admin-gated agent-create route is gone; provisioning is owner-gated and
	//    covered by TestProvisionAgent_OwnerGated).
	bsPriv, bsPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "bootstrap")
	bsAgentUser, err := svc.CreateAgent(context.Background(), orgID, "bootstrap", humanID, bsPub)
	if err != nil {
		t.Fatalf("seed bootstrap agent: %v", err)
	}
	if err := svc.GrantScope(context.Background(), bsAgentUser.ID, "agent:create", humanID); err != nil {
		t.Fatalf("grant agent:create: %v", err)
	}
	bsID := bsAgentUser.ID
```

(Replace the `adminPost(... "/agents" ...)` block + the `bsID, _ := bsAgent["id"].(string)` line. `bsPriv`/`bsPub` are reused below unchanged.) Apply the same store-seeding for any other test that created a bootstrap agent via the admin route.

- [ ] **7.7 — Full build + test:**

```
go build ./... && go test ./...
```
Expected output prefix: `ok` per package; no `FAIL`.

- [ ] **7.8 — Update the binary's bootstrap doc comment.** Edit `/Users/jacinta/Source/herald/cmd/herald/main.go` — update the `HERALD_ADMIN_TOKEN` doc line in the package comment:

Change:
```
//	HERALD_ADMIN_TOKEN  bearer token gating the bootstrap endpoints (required)
```
to:
```
//	HERALD_ADMIN_TOKEN  bearer token gating the bootstrap seed endpoint
//	                    POST /api/users only (required). All other provisioning
//	                    flows through user->org tokens (NEX-420).
```

- [ ] **7.9 — Commit:**

```
git commit -am "nex-420: owner-gate agent provisioning, org_role in token claims, shrink admin token to POST /api/users bootstrap

<trailer>"
```

---

# Task 8 — cwb-conformance fixtures rewrite (NEX-421)

**Goal:** Rewrite `internal/fixtures/ProvisionOrg` in the **cwb-conformance** repo to the user→org→provision flow so the conformance herald layer (NEX-405) passes LIVE.

**Repo:** `/Users/jacinta/Source/cwb-conformance` (DIFFERENT repo — all paths below are absolute). Run `go` commands from `/Users/jacinta/Source/cwb-conformance`.

**Live-only note:** This fixture can only be exercised end-to-end once herald org-ownership (Tasks 1–7) is **deployed** to the target (dMon). The conformance suite runs against a live gateway; there is no in-process herald. So the steps here are: rewrite the fixture to the new flow, `go build`/`go vet` it (compiles against the cwb-conformance module), and note that the live green-run is gated on deploy.

### New flow the fixture must implement

The old flow used the admin token for everything: create org, create humans, mint human tokens, create agents. The new flow:

1. **Bootstrap-seed the first user** via `POST /api/users` (admin token) — orgless human "alice".
2. **Mint alice a token** via `POST /api/humans/{id}/token` (admin token, MVP login stand-in) — this token now carries no org yet. **For the conformance harness, email verification is a precondition the live deploy must satisfy**; the harness sets it by seeding alice as email-verified out-of-band, OR the deploy runs with a conformance flag. Since the conformance target is a real herald, the fixture mints alice's token and, if the token lacks `email_verified`, org-create returns 403. **Document this as a live precondition** (the conformance deploy must seed verified emails) and have the fixture surface a clear failure.
3. **alice creates the org** via `POST /api/orgs` (alice's token) with `{name, slug}` — alice becomes owner.
4. **bob joins via an invite**: alice mints a `domain` or `email_list` invite (`POST /api/orgs/{org}/invites`), then bob (seeded + token-minted + email-verified) accepts it (`POST /api/invites/{token}/accept`).
5. **alice provisions the two agents** via `POST /api/orgs/{org}/agents` (alice's owner token) — same agent specs as before.

### Steps

- [ ] **8.1 — Read the current fixture + its callers.**

```
go vet ./... 2>&1 | head
```
Run from `/Users/jacinta/Source/cwb-conformance`. Expected output prefix: (clean, or pre-existing notes). Confirm `ProvisionOrg`'s signature `func ProvisionOrg(t *testing.T, tgt *target.Target) *TestOrg` and the `wire.PostJSON`/`wire.MintAgentToken` helpers exist (they do).

- [ ] **8.2 — Add a token-minting helper for the human login stand-in.** The fixture needs a helper that mints a human token with the conformance precondition that email is verified. Edit `/Users/jacinta/Source/cwb-conformance/internal/fixtures/org.go`. Add near the top (after imports):

```go
// mintHumanToken uses the admin MVP login stand-in to mint a token for a human.
// On the live target this token carries the user's email_verified claim only if
// the deployed herald seeds verified emails (a conformance-deploy precondition,
// NEX-421). If it does not, org-create returns 403 and ProvisionOrg fails fast
// with a clear message.
func mintHumanToken(t *testing.T, ctx context.Context, base, adminToken, humanID string) string {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	mustJSON(t, ctx, fmt.Sprintf("%s/api/humans/%s/token", base, humanID), adminToken, map[string]any{}, &tok)
	return tok.AccessToken
}
```

- [ ] **8.3 — Rewrite `ProvisionOrg`.** Replace the body of `ProvisionOrg` in `/Users/jacinta/Source/cwb-conformance/internal/fixtures/org.go` (keep the signature, the `Principal`/`TestOrg`/`agentSpec`/`fixtureAgents` types, and `mustJSON` unchanged):

```go
// ProvisionOrg provisions an ephemeral test org named cwb-test-<RunID> through
// the user->org->provision flow (NEX-421): the admin token seeds the first
// users; "alice" creates + owns the org; "bob" joins via an invite; alice
// provisions the two fixture agents as owner. Any failure fails the test
// immediately. Caller is responsible for Teardown (via t.Cleanup).
//
// LIVE PRECONDITION: the deployed herald must issue human tokens carrying
// email_verified=true for the seeded fixture users (org-create + invite-accept
// require a verified email). If it does not, the org-create step returns 403
// and this fixture fails fast.
func ProvisionOrg(t *testing.T, tgt *target.Target) *TestOrg {
	t.Helper()
	ctx := context.Background()
	base := tgt.HeraldBase()

	org := &TestOrg{
		Humans: map[string]Principal{},
		Agents: map[string]Principal{},
	}

	// 1. Bootstrap-seed alice (orgless) via the admin token, then mint her token.
	var alice struct {
		ID string `json:"id"`
	}
	mustJSON(t, ctx, base+"/api/users", tgt.AdminToken, map[string]any{"display_name": "alice"}, &alice)
	aliceTok := mintHumanToken(t, ctx, base, tgt.AdminToken, alice.ID)

	// 2. Alice creates + owns the org (user-token gated). slug must be DNS-safe;
	//    derive a lowercased, hyphen-safe slug from the run id.
	slug := "cwb-" + sanitizeSlug(tgt.RunID)
	var orgResp struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Tier string `json:"tier"`
	}
	mustJSON(t, ctx, base+"/api/orgs", aliceTok,
		map[string]any{"name": "cwb-test-" + tgt.RunID, "slug": slug}, &orgResp)
	org.OrgID = orgResp.ID

	// Re-mint alice's token now that she has org + org_role=owner on the record.
	aliceTok = mintHumanToken(t, ctx, base, tgt.AdminToken, alice.ID)
	org.Humans["alice"] = Principal{ID: alice.ID, Kind: "human", Token: aliceTok}

	// 3. Bob joins via an email_list invite. Seed bob, mint his token, alice
	//    mints the invite, bob accepts.
	var bob struct {
		ID string `json:"id"`
	}
	mustJSON(t, ctx, base+"/api/users", tgt.AdminToken, map[string]any{"display_name": "bob"}, &bob)
	bobTok := mintHumanToken(t, ctx, base, tgt.AdminToken, bob.ID)

	// Bob's seeded email is bob@<conformance-domain>; the invite allowlists it.
	// The live deploy controls the actual verified email; the email_list value
	// MUST match whatever email the deployed herald stamps for bob. The
	// conformance contract: seeded fixture users have email <name>@cwb.test.
	var invResp struct {
		Token string `json:"token"`
	}
	mustJSON(t, ctx, fmt.Sprintf("%s/api/orgs/%s/invites", base, org.OrgID), aliceTok, map[string]any{
		"policy_type":  "email_list",
		"policy_value": `["bob@cwb.test"]`,
		"role":         "member",
	}, &invResp)

	var acceptResp struct {
		Accepted bool `json:"accepted"`
	}
	mustJSON(t, ctx, fmt.Sprintf("%s/api/invites/%s/accept", base, invResp.Token), bobTok,
		map[string]any{}, &acceptResp)
	bobTok = mintHumanToken(t, ctx, base, tgt.AdminToken, bob.ID)
	org.Humans["bob"] = Principal{ID: bob.ID, Kind: "human", Token: bobTok}

	// 4. Alice (owner) provisions the two fixture agents under herself.
	for _, spec := range fixtureAgents {
		privB64, pubB64, err := DeriveAgentKey(tgt.RunID, spec.slug)
		if err != nil {
			t.Fatalf("derive %s key: %v", spec.slug, err)
		}
		var a struct {
			ID     string   `json:"id"`
			Scopes []string `json:"scopes"`
		}
		mustJSON(t, ctx, fmt.Sprintf("%s/api/orgs/%s/agents", base, org.OrgID), aliceTok, map[string]any{
			"display_name":      spec.slug,
			"responsible_human": alice.ID,
			"casket_pubkey":     pubB64,
			"scopes":            spec.scopes,
		}, &a)

		token, err := wire.MintAgentToken(ctx, tgt.TokenURL(), a.ID, privB64)
		if err != nil {
			t.Fatalf("mint token for %s (%s): %v", spec.slug, a.ID, err)
		}
		org.Agents[spec.slug] = Principal{
			ID:      a.ID,
			Kind:    "agent",
			Scopes:  spec.scopes,
			PrivB64: privB64,
			Token:   token,
		}
	}
	return org
}

// sanitizeSlug lowercases the run id and replaces any non [a-z0-9-] rune with a
// hyphen, collapsing the result into a DNS-safe label (herald validates slugs).
func sanitizeSlug(runID string) string {
	out := make([]byte, 0, len(runID))
	prevHyphen := false
	for i := 0; i < len(runID); i++ {
		c := runID[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
			prevHyphen = false
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			out = append(out, c)
			prevHyphen = false
		default:
			if !prevHyphen && len(out) > 0 {
				out = append(out, '-')
				prevHyphen = true
			}
		}
	}
	s := string(out)
	for len(s) > 0 && s[len(s)-1] == '-' {
		s = s[:len(s)-1]
	}
	if s == "" {
		s = "run"
	}
	if len(s) > 50 {
		s = s[:50]
	}
	return s
}
```

- [ ] **8.4 — Update the fixture test to match the new flow.** Read `/Users/jacinta/Source/cwb-conformance/internal/fixtures/org_test.go` and update any assertions that referenced the old admin-token org-create / human-create shape. The test runs against a target; if it is a live-target test guarded by an env check, ensure it still compiles. Minimal change: if the test asserts `org.OrgID != ""` and the two humans/agents exist, those invariants still hold under the new flow — keep them. Adjust only assertions that named the old endpoints. Run:

```
go vet ./internal/fixtures/
```
Run from `/Users/jacinta/Source/cwb-conformance`. Expected output prefix: (no output; exit 0).

- [ ] **8.5 — Build the conformance module:**

```
go build ./...
```
Run from `/Users/jacinta/Source/cwb-conformance`. Expected output prefix: (no output; exit 0).

- [ ] **8.6 — Run the unit-level fixture tests (the ones that do NOT require a live target):**

```
go test ./internal/fixtures/ ./internal/wire/
```
Run from `/Users/jacinta/Source/cwb-conformance`. Expected output prefix: `ok` for both packages (any live-target test should be skipped without a configured target; confirm it skips rather than fails).

- [ ] **8.7 — Commit (in the cwb-conformance repo):**

```
git commit -am "nex-421: rewrite ProvisionOrg to the user->org->invite->provision flow (herald org-ownership)

<trailer>"
```

- [ ] **8.8 — Note for the live run.** Record in the PR description: the conformance herald layer (NEX-405) can only be exercised LIVE once herald org-ownership (NEX-414…NEX-420) is deployed to the target AND the deployed herald seeds `email_verified` for the fixture users with addresses `<name>@cwb.test` (the live precondition baked into the fixture). Until then, the fixture compiles + unit-tests pass but the live layer stays pending-deploy.

---

## Coverage check (self-review summary)

Spec §10 build-sequence → tasks:
- §10.2 schema migration → **Task 1 (NEX-414)**.
- §10.3 org creation by user token → **Task 2 (NEX-415)**.
- §10.4 domain verification → **Task 3 (NEX-416)**.
- §10.5 invite links create/list/revoke + policy + delivery → **Task 4 (NEX-417)**.
- §10.6 accept invite + policy match + increment → **Task 5 (NEX-418)**.
- §10.7 branded email invites → **Task 6 (NEX-419)**.
- §10.8 re-gate provisioning + shrink admin token → **Task 7 (NEX-420)**.
- §10.9 org_role in token claims → **Task 7 (NEX-420)** (human-token in 2.6, agent-grant in 7.4).
- §10.10 cwb-conformance fixtures → **Task 8 (NEX-421)**.

Spec §6 API surface → tasks:
- `POST /api/orgs` (changed, user-token) → Task 2.
- `POST /api/orgs/{org}/domain` + `/verify` → Task 3.
- `POST/GET /api/orgs/{org}/invites`, `DELETE .../invites/{token}` → Task 4.
- `POST /api/invites/{token}/accept` → Task 5.
- `POST /api/orgs/{org}/agents` (changed, owner-gated) → Task 7.
- `POST /api/users` (bootstrap-only) → Task 7.
- `org_role` token claim → Tasks 2.6 + 7.4.

Path-A dependency, stated up front + handled per task:
- `email_verified` read from token claims (assume-from-amended-path-A; safe-default 403 if absent) → Tasks 2, 5.
- `Notifier` → local stub interface with no-op default + "replace when path-A lands" note → Task 6.

Cross-task type/signature consistency:
- Store methods/types added in Task 1 (`CreateOrgWithSlug`, `GetOrgBySlug`, `SetUserOrg`, `SetOrgDomain`, `CreateDomainChallenge`, `GetDomainChallenge`, `CreateInvite`, `GetInvite`, `ListInvites`, `IncrementInviteUses`, `RevokeInvite`; `Org.{Slug,Tier,Domain,DomainVerifiedAt}`, `User.OrgRole`, `Invite`, `DomainChallenge`, `Reserved*`/`Tier*`/`Role*`/`Policy*`/`Delivery*` consts) are exactly what Tasks 2–7 call.
- `requireOwner` (added in Task 2) is reused unchanged by Tasks 3, 4, 7 — gating reads the token org/org_role AND re-checks the stored record.
- `identity.InviteSpec`/`Message`/`Notifier`/`DomainResolver`/`DomainChallenge` are the only new identity-package exported types; each is defined before first use.
