package oidc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/CarriedWorldUniverse/herald/internal/issuer"
)

const federatedGrant = "urn:cwb:params:oauth:grant-type:federated"

type BindingResolver interface {
	ResolveBinding(ctx context.Context, orgID, issuerID, subject string) (userID string, err error)
}

// FederatedGrant exchanges an issuer-verified external attestation for the
// enrolled herald identity's normal access token. Claims are stamped from the
// store record, matching AgentGrant; only subject establishment differs.
type FederatedGrant struct {
	p       *Provider
	id      IdentityResolver
	bind    BindingResolver
	issuers *issuer.Registry
	refresh *RefreshIssuer
}

func NewFederatedGrant(p *Provider, id IdentityResolver, bind BindingResolver, issuers *issuer.Registry, refresh *RefreshIssuer) *FederatedGrant {
	return &FederatedGrant{p: p, id: id, bind: bind, issuers: issuers, refresh: refresh}
}

func (g *FederatedGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "attestation rejected")
		return
	}
	if r.Form.Get("grant_type") != federatedGrant {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "attestation rejected")
		return
	}
	orgID := r.Form.Get("org_id")
	issuerID := r.Form.Get("issuer_id")
	attestation := r.Form.Get("attestation")
	if orgID == "" || issuerID == "" || attestation == "" {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "attestation rejected")
		return
	}

	tok, subject, err := g.issue(r.Context(), orgID, issuerID, attestation)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "attestation rejected")
		return
	}
	resp := map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	}
	if g.refresh != nil {
		if rtok, err := g.refresh.Issue(r.Context(), subject); err != nil {
			log.Printf("oidc: refresh.Issue for federated identity %s: %v", subject, err)
		} else {
			resp["refresh_token"] = rtok
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (g *FederatedGrant) issue(ctx context.Context, orgID, issuerID, attestation string) (token, subject string, err error) {
	if g.issuers == nil {
		return "", "", errors.New("issuer registry unavailable")
	}
	verifier, ok := g.issuers.Verifier(issuerID)
	if !ok {
		return "", "", errors.New("unknown issuer verifier")
	}
	externalSubject, err := verifier.Verify(ctx, attestation)
	if err != nil {
		return "", "", fmt.Errorf("verify attestation: %w", err)
	}
	userID, err := g.bind.ResolveBinding(ctx, orgID, issuerID, externalSubject)
	if err != nil {
		return "", "", fmt.Errorf("resolve binding: %w", err)
	}
	u, err := g.id.GetUser(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("unknown identity: %w", err)
	}
	if !g.id.IsActive(ctx, u.ID) {
		return "", "", errors.New("identity inactive")
	}
	out, err := accessClaims(ctx, g.id, u)
	if err != nil {
		return "", "", fmt.Errorf("claims: %w", err)
	}
	signed, err := g.p.SignToken(out)
	if err != nil {
		return "", "", err
	}
	return signed, u.ID, nil
}
