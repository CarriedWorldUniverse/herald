// Package grpcadmin is herald's admin/internal API served over gRPC behind
// interchange (Phase 4 of the CWB gRPC mesh). It implements cwb.herald.v1's
// AdminService + AgentService over the SAME identity/token/purger backends the
// HTTP adminapi uses — the difference is authorization: instead of a static
// admin token, authority is derived from the verified caller identity injected
// by interchange as cwb-* gRPC metadata.
//
//	herald:platform-admin (the admin org's owner)  → may act on ANY org
//	herald:org-admin (bound to the caller's org)    → may act on its OWN org only
//	CreateOrg                                        → platform-admin (Phase 4;
//	  the self-serve "new account creates its org" path is NEX-413 onboarding)
//
// AgentService.GetAgentByFingerprint is the internal exception: it carries no
// cwb-* identity (cairn's SSH path has a pubkey, not a token) and is authorized
// by the mTLS client cert alone — so it is dialed DIRECTLY, never via the edge.
package grpcadmin

import (
	"context"
	"crypto/ed25519"
	"strings"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Identity is the full org/human/agent/product admin surface the gRPC
// AdminService + genesis seeding drive. (identity.Service satisfies it.)
type Identity interface {
	CreateOrg(ctx context.Context, name string) (store.Org, error)
	CreateOrgWithProducts(ctx context.Context, name string, products []string) (store.Org, error)
	CreateHuman(ctx context.Context, orgID, displayName string) (store.User, error)
	CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	RegisterIssuer(ctx context.Context, orgID, kind, ref string) (store.Issuer, error)
	EnrollFederatedIdentity(ctx context.Context, orgID, displayName, issuerID, subject string) (store.User, error)
	GrantScope(ctx context.Context, userID, scope, grantedBy string) error
	SetHumanPassword(ctx context.Context, userID, plaintext string) error
	GetUser(ctx context.Context, id string) (store.User, error)
	GetOrg(ctx context.Context, orgID string) (store.Org, error)
	GetAgentByFingerprint(ctx context.Context, fp string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
	Products(ctx context.Context, orgID string) (map[string]bool, error)
	EnableProduct(ctx context.Context, orgID, product string) error
	DisableProduct(ctx context.Context, orgID, product string) error
	ListOrgs(ctx context.Context) ([]store.Org, error)
	DeleteOrg(ctx context.Context, id string) error
	// SetAdminOrg publishes which org is the control plane, so the tenant
	// invariant (no control-plane scope for non-admin orgs) can be enforced.
	SetAdminOrg(orgID string)
}

// TokenSigner signs herald tokens (the DeleteOrg fan-out mints a purge token).
type TokenSigner interface {
	SignToken(claims map[string]any) (string, error)
}

// OrgPurger fans an org wipe out to the data pillars (herald's internal/purge).
type OrgPurger interface {
	PurgeOrg(ctx context.Context, orgID, purgeToken string) (map[string]string, error)
}

// Admin scopes (identity-derived authority; replace the static admin token).
// The scope strings are owned by the identity domain layer — alias them so the
// values cannot drift between the authz checks here and the role vocabulary.
const (
	ScopePlatformAdmin = identity.ScopePlatformAdmin
	ScopeOrgAdmin      = identity.ScopeOrgAdmin
)

// caller is the verified identity from interchange-injected cwb-* metadata.
type caller struct {
	Subject string
	Org     string
	Scopes  []string
}

func (c caller) has(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (c caller) isPlatformAdmin() bool { return c.has(ScopePlatformAdmin) }

// canAdminOrg reports whether the caller may perform admin ops on targetOrg:
// platform-admin (any org), or org-admin bound to that same org.
func (c caller) canAdminOrg(targetOrg string) bool {
	if c.isPlatformAdmin() {
		return true
	}
	return c.has(ScopeOrgAdmin) && c.Org != "" && c.Org == targetOrg
}

// callerFromCtx reads the cwb-* metadata interchange injects after verifying the
// herald JWT. ok is false when no verified subject is present.
func callerFromCtx(ctx context.Context) (caller, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return caller{}, false
	}
	get := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	sub := get("cwb-subject")
	if sub == "" {
		return caller{}, false
	}
	return caller{Subject: sub, Org: get("cwb-org"), Scopes: strings.Fields(get("cwb-scopes"))}, true
}

// requirePlatformAdmin / requireOrgAdmin return a gRPC status error when the
// caller lacks the authority, else the caller.
func requirePlatformAdmin(ctx context.Context) (caller, error) {
	c, ok := callerFromCtx(ctx)
	if !ok {
		return caller{}, status.Error(codes.Unauthenticated, "missing identity")
	}
	if !c.isPlatformAdmin() {
		return caller{}, status.Error(codes.PermissionDenied, "requires "+ScopePlatformAdmin)
	}
	return c, nil
}

func requireOrgAdmin(ctx context.Context, targetOrg string) (caller, error) {
	c, ok := callerFromCtx(ctx)
	if !ok {
		return caller{}, status.Error(codes.Unauthenticated, "missing identity")
	}
	if !c.canAdminOrg(targetOrg) {
		return caller{}, status.Error(codes.PermissionDenied, "requires admin of org "+targetOrg)
	}
	return c, nil
}

// Servers bundles herald's gRPC service implementations over the existing
// identity / token / purger backends (the same ones adminapi uses).
type Servers struct {
	id     Identity
	tokens TokenSigner
	purger OrgPurger
}

// New builds the gRPC service implementations.
func New(id Identity, tokens TokenSigner, purger OrgPurger) *Servers {
	return &Servers{id: id, tokens: tokens, purger: purger}
}

// Register registers AdminService + AgentService on g.
func (s *Servers) Register(g grpc.ServiceRegistrar) {
	heraldv1.RegisterAdminServiceServer(g, &adminServer{s: s})
	heraldv1.RegisterAgentServiceServer(g, &agentServer{s: s})
}
