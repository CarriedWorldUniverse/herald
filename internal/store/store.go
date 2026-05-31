// Package store is herald's identity persistence: orgs, users (human|agent,
// one type with a kind discriminator), and scope grants. See the MVP spec §3.
//
// The Store interface is the seam; SQLite is the MVP implementation. Domain
// logic (create-agent validation, block cascade, fingerprinting) lives one
// layer up in internal/identity — the store is a thin typed CRUD surface.
package store

import (
	"context"
	"errors"
)

// Kind discriminates the two user kinds. Same record, different auth method:
// humans log in (login_secret); agents present a casket-signed JWT (casket_pubkey).
type Kind string

const (
	KindHuman Kind = "human"
	KindAgent Kind = "agent"
)

// Status is the active/blocked lifecycle flag on orgs and users.
type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
	// StatusPending is a self-provisioned agent awaiting human validation.
	// Pending agents exist but cannot authenticate until a human flips them
	// to active (human-in-the-loop at account birth).
	StatusPending Status = "pending"
)

// ErrNotFound is returned by Get* when no row matches.
var ErrNotFound = errors.New("store: not found")

// ErrDuplicateFingerprint is returned when an agent registration would reuse a
// casket fingerprint already bound to another agent. A casket key = one agent.
var ErrDuplicateFingerprint = errors.New("store: casket fingerprint already registered")

// Org is a tenant + accountability root. Flat for MVP (no manager tree).
type Org struct {
	ID        string
	Name      string
	Status    Status
	CreatedAt string
}

// User is a human or an agent. The fields used depend on Kind:
//   - human: LoginSecret set; Casket* and ResponsibleHuman empty.
//   - agent: CasketPubkey + CasketFingerprint + ResponsibleHuman set; LoginSecret empty.
//
// ID is the canonical entity UUID that consumers key on.
type User struct {
	ID                string
	OrgID             string
	Kind              Kind
	DisplayName       string
	Status            Status
	LoginSecret       string // human only
	CasketPubkey      []byte // agent only (ed25519 public key)
	CasketFingerprint string // agent only
	ResponsibleHuman  string // agent only (FK -> user.id of a human in the same org)
	CreatedAt         string
}

// ScopeGrant is one capability granted to a user, with the granter recorded
// for accountability ("who authorized this?").
type ScopeGrant struct {
	ID        string
	UserID    string
	Scope     string
	GrantedBy string
	CreatedAt string
}

// Store is herald's persistence seam. Implementations MUST be safe for
// concurrent use.
type Store interface {
	// Orgs.
	CreateOrg(ctx context.Context, name string) (Org, error)
	GetOrg(ctx context.Context, id string) (Org, error)
	// DeleteOrg removes an org and ALL its rows (users, their scope grants,
	// product overrides) in one transaction. Idempotent: an absent org is a
	// no-op (no error).
	DeleteOrg(ctx context.Context, id string) error
	// ListOrgs returns every org (id, name, status).
	ListOrgs(ctx context.Context) ([]Org, error)

	// Users. CreateUser assigns an ID if the passed User.ID is empty and
	// persists the row as-is (validation is the identity layer's job).
	CreateUser(ctx context.Context, u User) (User, error)
	GetUser(ctx context.Context, id string) (User, error)
	GetUserByCasketFingerprint(ctx context.Context, fp string) (User, error)
	ListAgentsByResponsibleHuman(ctx context.Context, humanID string) ([]User, error)
	SetUserStatus(ctx context.Context, id string, s Status) error
	SetLoginSecret(ctx context.Context, id, hash string) error
	SetOrgStatus(ctx context.Context, id string, s Status) error

	// Scopes.
	GrantScope(ctx context.Context, userID, scope, grantedBy string) (ScopeGrant, error)
	RevokeScope(ctx context.Context, userID, scope string) error
	ListScopes(ctx context.Context, userID string) ([]string, error)

	// Product entitlement (deny-list: an absent row OR enabled=1 means
	// the product is enabled for the org).
	SetProductEnabled(ctx context.Context, orgID, product string, enabled bool) error
	IsProductEnabled(ctx context.Context, orgID, product string) (bool, error)
	ListProductOverrides(ctx context.Context, orgID string) (map[string]bool, error)

	// Close releases resources.
	Close() error
}
