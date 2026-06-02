package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// SQLite is the modernc.org/sqlite-backed Store (CGO-free). Safe for
// concurrent use: *sql.DB is, and SQLite serializes writes.
type SQLite struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and applies the schema.
// Use ":memory:" for tests. For a file DB, foreign keys + WAL are enabled.
func Open(path string) (*SQLite, error) {
	dsn := path
	if path == ":memory:" {
		// Shared cache so the single *sql.DB connection pool sees one in-mem db.
		dsn = "file::memory:?cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store.Open: %w", err)
	}
	// One connection for :memory: shared-cache safety; file DBs are fine too.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: enable fk: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store.Open: apply schema: %w", err)
	}
	return &SQLite{db: db}, nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func newID() string { return uuid.NewString() }

func (s *SQLite) CreateOrg(ctx context.Context, name string) (Org, error) {
	o := Org{ID: newID(), Name: name, Status: StatusActive}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO org (id, name, status) VALUES (?, ?, ?)`,
		o.ID, o.Name, string(o.Status))
	if err != nil {
		return Org{}, fmt.Errorf("CreateOrg: %w", err)
	}
	return s.GetOrg(ctx, o.ID)
}

func (s *SQLite) GetOrg(ctx context.Context, id string) (Org, error) {
	var o Org
	var status string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, status, created_at FROM org WHERE id = ?`, id).
		Scan(&o.ID, &o.Name, &status, &o.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Org{}, ErrNotFound
	}
	if err != nil {
		return Org{}, fmt.Errorf("GetOrg: %w", err)
	}
	o.Status = Status(status)
	return o, nil
}

func (s *SQLite) CreateUser(ctx context.Context, u User) (User, error) {
	if u.ID == "" {
		u.ID = newID()
	}
	if u.Status == "" {
		u.Status = StatusActive
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user (id, org_id, kind, display_name, status,
		                  login_secret, casket_pubkey, casket_fingerprint, responsible_human)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.OrgID, string(u.Kind), u.DisplayName, string(u.Status),
		nullStr(u.LoginSecret), nullBytes(u.CasketPubkey), nullStr(u.CasketFingerprint), nullStr(u.ResponsibleHuman))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: user.casket_fingerprint") {
			return User{}, ErrDuplicateFingerprint
		}
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
	return s.GetUser(ctx, u.ID)
}

func (s *SQLite) GetUser(ctx context.Context, id string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE id = ?`, id))
}

func (s *SQLite) GetUserByCasketFingerprint(ctx context.Context, fp string) (User, error) {
	return s.scanUser(s.db.QueryRowContext(ctx, userSelect+` WHERE casket_fingerprint = ?`, fp))
}

// GetUserByDisplayName resolves a human by display name (login-by-email). It
// matches kind='human' only and requires EXACTLY one match — zero or many both
// yield ErrNotFound, so an ambiguous display name can never resolve to a wrong
// user.
func (s *SQLite) GetUserByDisplayName(ctx context.Context, displayName string) (User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` WHERE display_name = ? AND kind = 'human' LIMIT 2`, displayName)
	if err != nil {
		return User{}, fmt.Errorf("GetUserByDisplayName: %w", err)
	}
	defer rows.Close()
	var found []User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return User{}, err
		}
		found = append(found, u)
	}
	if err := rows.Err(); err != nil {
		return User{}, err
	}
	if len(found) != 1 {
		return User{}, ErrNotFound // 0 (none) or >1 (ambiguous) both fail closed
	}
	return found[0], nil
}

func (s *SQLite) ListAgentsByResponsibleHuman(ctx context.Context, humanID string) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, userSelect+` WHERE responsible_human = ?`, humanID)
	if err != nil {
		return nil, fmt.Errorf("ListAgentsByResponsibleHuman: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUserRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *SQLite) SetUserStatus(ctx context.Context, id string, st Status) error {
	res, err := s.db.ExecContext(ctx, `UPDATE user SET status = ? WHERE id = ?`, string(st), id)
	if err != nil {
		return fmt.Errorf("SetUserStatus: %w", err)
	}
	return mustAffect(res)
}

// SetLoginSecret stores a human's password hash (bcrypt) in login_secret.
func (s *SQLite) SetLoginSecret(ctx context.Context, id, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE user SET login_secret = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("SetLoginSecret: %w", err)
	}
	return mustAffect(res)
}

func (s *SQLite) SetOrgStatus(ctx context.Context, id string, st Status) error {
	res, err := s.db.ExecContext(ctx, `UPDATE org SET status = ? WHERE id = ?`, string(st), id)
	if err != nil {
		return fmt.Errorf("SetOrgStatus: %w", err)
	}
	return mustAffect(res)
}

func (s *SQLite) GrantScope(ctx context.Context, userID, scope, grantedBy string) (ScopeGrant, error) {
	g := ScopeGrant{ID: newID(), UserID: userID, Scope: scope, GrantedBy: grantedBy}
	// Idempotent: ON CONFLICT(user_id, scope) keep the existing row.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scope_grant (id, user_id, scope, granted_by) VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, scope) DO NOTHING`,
		g.ID, g.UserID, g.Scope, nullStr(g.GrantedBy))
	if err != nil {
		return ScopeGrant{}, fmt.Errorf("GrantScope: %w", err)
	}
	return g, nil
}

func (s *SQLite) RevokeScope(ctx context.Context, userID, scope string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM scope_grant WHERE user_id = ? AND scope = ?`, userID, scope)
	if err != nil {
		return fmt.Errorf("RevokeScope: %w", err)
	}
	return nil
}

func (s *SQLite) ListScopes(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT scope FROM scope_grant WHERE user_id = ? ORDER BY scope`, userID)
	if err != nil {
		return nil, fmt.Errorf("ListScopes: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

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
	// RFC3339 UTC to match expires_at's format (so RevokedAt is parseable by
	// any consumer, not just emptiness-checked).
	_, err := s.db.ExecContext(ctx,
		`UPDATE refresh_token SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')
		   WHERE chain_id = ? AND revoked_at IS NULL`, chainID)
	if err != nil {
		return fmt.Errorf("RevokeRefreshChain: %w", err)
	}
	return nil
}

// --- scan helpers ---

const userSelect = `SELECT id, org_id, kind, display_name, status,
	login_secret, casket_pubkey, casket_fingerprint, responsible_human, created_at FROM user`

type scanner interface{ Scan(dest ...any) error }

func (s *SQLite) scanUser(row scanner) (User, error) {
	u, err := scanUserRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func scanUserRow(row scanner) (User, error) {
	var u User
	var kind, status string
	var login, fp, resp sql.NullString
	var pub []byte
	if err := row.Scan(&u.ID, &u.OrgID, &kind, &u.DisplayName, &status,
		&login, &pub, &fp, &resp, &u.CreatedAt); err != nil {
		return User{}, err
	}
	u.Kind = Kind(kind)
	u.Status = Status(status)
	u.LoginSecret = login.String
	u.CasketPubkey = pub
	u.CasketFingerprint = fp.String
	u.ResponsibleHuman = resp.String
	return u, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func mustAffect(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

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
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM scope_grant WHERE user_id IN (SELECT id FROM user WHERE org_id=?)
		    OR granted_by IN (SELECT id FROM user WHERE org_id=?)`, id, id); err != nil {
		return fmt.Errorf("DeleteOrg: scope_grant: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM org_product WHERE org_id=?`, id); err != nil {
		return fmt.Errorf("DeleteOrg: org_product: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM refresh_token WHERE user_id IN (SELECT id FROM user WHERE org_id=?)`, id); err != nil {
		return fmt.Errorf("DeleteOrg: refresh_token: %w", err)
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
