package grpcadmin

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminServer struct {
	heraldv1.UnimplementedAdminServiceServer
	s *Servers
}

// CreateOrg — platform-admin only in Phase 4 (the self-serve new-account path
// is the NEX-413 onboarding flow). Optionally enables initial products.
func (a *adminServer) CreateOrg(ctx context.Context, r *heraldv1.CreateOrgRequest) (*heraldv1.CreateOrgResponse, error) {
	if _, err := requirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	org, err := a.s.id.CreateOrgWithProducts(ctx, r.Name, r.Products)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.CreateOrgResponse{Org: &heraldv1.Org{Id: org.ID, Name: org.Name}}, nil
}

func (a *adminServer) ListOrgs(ctx context.Context, _ *heraldv1.ListOrgsRequest) (*heraldv1.ListOrgsResponse, error) {
	if _, err := requirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	orgs, err := a.s.id.ListOrgs(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*heraldv1.Org, len(orgs))
	for i, o := range orgs {
		out[i] = &heraldv1.Org{Id: o.ID, Name: o.Name}
	}
	return &heraldv1.ListOrgsResponse{Orgs: out}, nil
}

// DeleteOrg — platform-admin only; confirm-by-name, then fan out the purge to
// the pillars (mirrors the HTTP orchestration) and delete herald's org last.
func (a *adminServer) DeleteOrg(ctx context.Context, r *heraldv1.DeleteOrgRequest) (*heraldv1.DeleteOrgResponse, error) {
	if _, err := requirePlatformAdmin(ctx); err != nil {
		return nil, err
	}
	org, err := a.s.id.GetOrg(ctx, r.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "org not found")
	}
	if r.Name == "" || r.Name != org.Name {
		return nil, status.Error(codes.FailedPrecondition, "org name confirmation does not match")
	}
	token, err := a.s.tokens.SignToken(map[string]any{
		"sub":      "system:purge",
		"kind":     string(store.KindAgent),
		"org":      r.Id,
		"scope":    identity.ScopeOrgPurge,
		"products": identity.CanonicalProducts,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "mint purge token failed")
	}
	pillars, err := a.s.purger.PurgeOrg(ctx, r.Id, token)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "pillar purge failed: "+err.Error())
	}
	if err := a.s.id.DeleteOrg(ctx, r.Id); err != nil {
		return nil, status.Error(codes.Internal, "herald org delete failed: "+err.Error())
	}
	out := make([]string, 0, len(pillars))
	for p := range pillars {
		out = append(out, p)
	}
	return &heraldv1.DeleteOrgResponse{Deleted: r.Id, Pillars: out}, nil
}

func (a *adminServer) GetProducts(ctx context.Context, r *heraldv1.GetProductsRequest) (*heraldv1.GetProductsResponse, error) {
	if _, err := requireOrgAdmin(ctx, r.Org); err != nil {
		return nil, err
	}
	m, err := a.s.id.Products(ctx, r.Org)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.GetProductsResponse{Products: m}, nil
}

func (a *adminServer) EnableProduct(ctx context.Context, r *heraldv1.EnableProductRequest) (*heraldv1.EnableProductResponse, error) {
	if _, err := requireOrgAdmin(ctx, r.Org); err != nil {
		return nil, err
	}
	if err := a.s.id.EnableProduct(ctx, r.Org, r.Product); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	m, err := a.s.id.Products(ctx, r.Org)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.EnableProductResponse{Products: m}, nil
}

func (a *adminServer) DisableProduct(ctx context.Context, r *heraldv1.DisableProductRequest) (*heraldv1.DisableProductResponse, error) {
	if _, err := requireOrgAdmin(ctx, r.Org); err != nil {
		return nil, err
	}
	if err := a.s.id.DisableProduct(ctx, r.Org, r.Product); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	m, err := a.s.id.Products(ctx, r.Org)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.DisableProductResponse{Products: m}, nil
}

func (a *adminServer) CreateHuman(ctx context.Context, r *heraldv1.CreateHumanRequest) (*heraldv1.CreateHumanResponse, error) {
	c, err := requireOrgAdmin(ctx, r.Org)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.DisplayName) == "" {
		return nil, status.Error(codes.InvalidArgument, "display_name required")
	}
	h, err := a.s.id.CreateHuman(ctx, r.Org, r.DisplayName)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := a.grantAll(ctx, h.ID, r.Scopes, c.Subject); err != nil {
		return nil, err
	}
	return &heraldv1.CreateHumanResponse{Human: &heraldv1.Human{Id: h.ID, DisplayName: h.DisplayName, Org: h.OrgID}}, nil
}

func (a *adminServer) CreateAgent(ctx context.Context, r *heraldv1.CreateAgentRequest) (*heraldv1.CreateAgentResponse, error) {
	c, err := requireOrgAdmin(ctx, r.Org)
	if err != nil {
		return nil, err
	}
	if r.ResponsibleHuman == "" {
		return nil, status.Error(codes.InvalidArgument, "responsible_human required")
	}
	raw, derr := base64.StdEncoding.DecodeString(r.CasketPubkey)
	if derr != nil || len(raw) != ed25519.PublicKeySize {
		return nil, status.Error(codes.InvalidArgument, "casket_pubkey must be base64(std) of a 32-byte ed25519 key")
	}
	ag, err := a.s.id.CreateAgent(ctx, r.Org, r.DisplayName, r.ResponsibleHuman, ed25519.PublicKey(raw))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if err := a.grantAll(ctx, ag.ID, r.Scopes, c.Subject); err != nil {
		return nil, err
	}
	scopes, _ := a.s.id.EffectiveScopes(ctx, ag.ID)
	return &heraldv1.CreateAgentResponse{Agent: toProtoAgent(ag, scopes)}, nil
}

func (a *adminServer) RegisterIssuer(ctx context.Context, r *heraldv1.RegisterIssuerRequest) (*heraldv1.RegisterIssuerResponse, error) {
	if _, err := requireOrgAdmin(ctx, r.Org); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.Kind) == "" {
		return nil, status.Error(codes.InvalidArgument, "kind required")
	}
	if strings.TrimSpace(r.Ref) == "" {
		return nil, status.Error(codes.InvalidArgument, "ref required")
	}
	iss, err := a.s.id.RegisterIssuer(ctx, r.Org, r.Kind, r.Ref)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.RegisterIssuerResponse{Issuer: toProtoIssuer(iss)}, nil
}

func (a *adminServer) EnrollFederatedIdentity(ctx context.Context, r *heraldv1.EnrollFederatedIdentityRequest) (*heraldv1.EnrollFederatedIdentityResponse, error) {
	if _, err := requireOrgAdmin(ctx, r.Org); err != nil {
		return nil, err
	}
	if strings.TrimSpace(r.DisplayName) == "" {
		return nil, status.Error(codes.InvalidArgument, "display_name required")
	}
	if strings.TrimSpace(r.IssuerId) == "" {
		return nil, status.Error(codes.InvalidArgument, "issuer_id required")
	}
	if strings.TrimSpace(r.Subject) == "" {
		return nil, status.Error(codes.InvalidArgument, "subject required")
	}
	u, err := a.s.id.EnrollFederatedIdentity(ctx, r.Org, r.DisplayName, r.IssuerId, r.Subject)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateFederatedBinding) {
			return nil, status.Error(codes.AlreadyExists, "federated identity already enrolled")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &heraldv1.EnrollFederatedIdentityResponse{Identity: toProtoAgent(u, nil)}, nil
}

func (a *adminServer) SetHumanPassword(ctx context.Context, r *heraldv1.SetHumanPasswordRequest) (*heraldv1.SetHumanPasswordResponse, error) {
	human, err := a.s.id.GetUser(ctx, r.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "human not found")
	}
	if _, err := requireOrgAdmin(ctx, human.OrgID); err != nil {
		return nil, err
	}
	if len(r.Password) < 8 {
		return nil, status.Error(codes.InvalidArgument, "password must be at least 8 characters")
	}
	if err := a.s.id.SetHumanPassword(ctx, r.Id, r.Password); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &heraldv1.SetHumanPasswordResponse{}, nil
}

func (a *adminServer) IssueHumanToken(ctx context.Context, r *heraldv1.IssueHumanTokenRequest) (*heraldv1.IssueHumanTokenResponse, error) {
	human, err := a.s.id.GetUser(ctx, r.Id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "human not found")
	}
	if _, err := requireOrgAdmin(ctx, human.OrgID); err != nil {
		return nil, err
	}
	if human.Kind != store.KindHuman {
		return nil, status.Error(codes.InvalidArgument, "not a human")
	}
	scopes, _ := a.s.id.EffectiveScopes(ctx, human.ID)
	claims := map[string]any{
		"sub":   human.ID,
		"kind":  string(store.KindHuman),
		"org":   human.OrgID,
		"scope": strings.Join(scopes, " "),
	}
	if human.CasketFingerprint != "" {
		claims["human_fp"] = human.CasketFingerprint
	}
	tok, err := a.s.tokens.SignToken(claims)
	if err != nil {
		return nil, status.Error(codes.Internal, "sign failed")
	}
	return &heraldv1.IssueHumanTokenResponse{AccessToken: tok, TokenType: "Bearer"}, nil
}

// Me returns the caller's own authoritative identity record. Any authenticated
// principal may call it for themselves — no admin scope (callerFromCtx only).
func (a *adminServer) Me(ctx context.Context, _ *heraldv1.MeRequest) (*heraldv1.MeResponse, error) {
	c, ok := callerFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
	}
	user, err := a.s.id.GetUser(ctx, c.Subject)
	if err != nil {
		return nil, status.Error(codes.NotFound, "identity not found")
	}
	org, err := a.s.id.GetOrg(ctx, user.OrgID)
	if err != nil {
		return nil, status.Error(codes.Internal, "org lookup failed")
	}
	scopes, err := a.s.id.EffectiveScopes(ctx, user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "scope lookup failed")
	}
	return &heraldv1.MeResponse{User: &heraldv1.UserInfo{
		Id:               user.ID,
		Kind:             string(user.Kind),
		DisplayName:      user.DisplayName,
		Org:              user.OrgID,
		OrgName:          org.Name,
		Status:           string(user.Status),
		Scopes:           scopes,
		ResponsibleHuman: user.ResponsibleHuman,
		Fingerprint:      user.CasketFingerprint,
	}}, nil
}

// grantAll grants each scope to userID on behalf of grantedBy (an FK-valid user
// id — the verified caller). "role:<name>" entries expand to their bundle scopes
// first, so onboarding can grant e.g. role:org-owner. A grant the tenant
// invariant refuses (a control-plane scope to a non-admin org) is a
// PermissionDenied; an unknown role is InvalidArgument.
func (a *adminServer) grantAll(ctx context.Context, userID string, scopes []string, grantedBy string) error {
	expanded, err := identity.ExpandScopes(scopes)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	for _, sc := range expanded {
		if err := a.s.id.GrantScope(ctx, userID, sc, grantedBy); err != nil {
			if errors.Is(err, identity.ErrControlPlaneScopeForTenant) {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			return status.Error(codes.Internal, "grant scope: "+err.Error())
		}
	}
	return nil
}

func toProtoAgent(u store.User, scopes []string) *heraldv1.Agent {
	return &heraldv1.Agent{
		Id:               u.ID,
		Kind:             string(u.Kind),
		DisplayName:      u.DisplayName,
		Org:              u.OrgID,
		ResponsibleHuman: u.ResponsibleHuman,
		Fingerprint:      u.CasketFingerprint,
		Status:           string(u.Status),
		Active:           u.Status == store.StatusActive,
		Scopes:           scopes,
	}
}

func toProtoIssuer(iss store.Issuer) *heraldv1.Issuer {
	return &heraldv1.Issuer{
		Id:   iss.ID,
		Org:  iss.OrgID,
		Kind: iss.Kind,
		Ref:  iss.Ref,
	}
}
