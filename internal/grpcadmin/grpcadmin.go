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
	"strings"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Admin scopes (identity-derived authority; replace the static admin token).
const (
	ScopePlatformAdmin = "herald:platform-admin"
	ScopeOrgAdmin      = "herald:org-admin"
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
	id     adminapi.Identity
	tokens adminapi.TokenIssuer
	purger adminapi.OrgPurger
}

// New builds the gRPC service implementations.
func New(id adminapi.Identity, tokens adminapi.TokenIssuer, purger adminapi.OrgPurger) *Servers {
	return &Servers{id: id, tokens: tokens, purger: purger}
}

// Register registers AdminService + AgentService on g.
func (s *Servers) Register(g grpc.ServiceRegistrar) {
	heraldv1.RegisterAdminServiceServer(g, &adminServer{s: s})
	heraldv1.RegisterAgentServiceServer(g, &agentServer{s: s})
}
