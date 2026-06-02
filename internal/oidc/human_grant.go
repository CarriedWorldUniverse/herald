package oidc

import (
	"context"
	"net/http"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// passwordGrant is the OAuth2 Resource-Owner-Password grant humans use for v0
// login (spec §5b). ROPC is deprecated in OAuth 2.1; acceptable for first-party
// v0, with auth-code + passkey as the hardening path.
const passwordGrant = "password"

// HumanResolver is the slice of the identity service the human grant needs:
// password verification plus the shared claim-building resolver.
type HumanResolver interface {
	VerifyHumanPassword(ctx context.Context, userID, plaintext string) (store.User, error)
	IdentityResolver
}

// HumanGrant implements the password token endpoint: a human presents their
// user id + password; herald verifies the bcrypt hash and issues a kind:human
// access token. Mirrors AgentGrant's shape.
type HumanGrant struct {
	p       *Provider
	id      HumanResolver
	refresh *RefreshIssuer
}

// NewHumanGrant wires the grant to a provider + human resolver.
func NewHumanGrant(p *Provider, id HumanResolver, refresh *RefreshIssuer) *HumanGrant {
	return &HumanGrant{p: p, id: id, refresh: refresh}
}

// ServeToken handles POST /token for the password grant.
func (g *HumanGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	username := r.Form.Get("username")
	password := r.Form.Get("password")
	if username == "" || password == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing username or password")
		return
	}
	u, err := g.id.VerifyHumanPassword(r.Context(), username, password)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "login rejected")
		return
	}
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
}
