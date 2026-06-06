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

// Issuer is an org-scoped external identity provider. Kind selects the
// verifier implementation (for NEX-474: k8s); Ref is the deployment-specific
// issuer reference used by operators to distinguish clusters/providers.
type Issuer struct {
	ID        string
	OrgID     string
	Kind      string
	Ref       string
	CreatedAt string
}

// FederatedBinding enrolls an external {issuer, subject} as one herald user.
// The tuple (OrgID, IssuerID, Subject) is unique, so a verified external
// subject resolves to exactly one identity inside an org and never across orgs.
type FederatedBinding struct {
	ID        string
	OrgID     string
	UserID    string
	IssuerID  string
	Subject   string
	CreatedAt string
}

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
	// GetUserByDisplayName resolves a HUMAN by display name (e.g. an email used
	// as the login username). Returns ErrNotFound if zero OR more than one human
	// matches (ambiguous logins must fail closed, never resolve to a wrong user).
	GetUserByDisplayName(ctx context.Context, displayName string) (User, error)
	ListAgentsByResponsibleHuman(ctx context.Context, humanID string) ([]User, error)
	SetUserStatus(ctx context.Context, id string, s Status) error
	SetLoginSecret(ctx context.Context, id, hash string) error
	SetOrgStatus(ctx context.Context, id string, s Status) error

	// Scopes.
	GrantScope(ctx context.Context, userID, scope, grantedBy string) (ScopeGrant, error)
	RevokeScope(ctx context.Context, userID, scope string) error
	ListScopes(ctx context.Context, userID string) ([]string, error)

	// Federated identity enrollment.
	RegisterIssuer(ctx context.Context, iss Issuer) (Issuer, error)
	AddBinding(ctx context.Context, b FederatedBinding) (FederatedBinding, error)
	ResolveBinding(ctx context.Context, orgID, issuerID, subject string) (userID string, err error)

	// Refresh tokens (rotating; see RefreshToken).
	CreateRefreshToken(ctx context.Context, rt RefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (RefreshToken, error)
	// RevokeRefreshChain marks every still-live row in the chain revoked.
	// Idempotent.
	RevokeRefreshChain(ctx context.Context, chainID string) error

	// Product entitlement (deny-list: an absent row OR enabled=1 means
	// the product is enabled for the org).
	SetProductEnabled(ctx context.Context, orgID, product string, enabled bool) error
	IsProductEnabled(ctx context.Context, orgID, product string) (bool, error)
	ListProductOverrides(ctx context.Context, orgID string) (map[string]bool, error)

	// Close releases resources.
	Close() error
}
