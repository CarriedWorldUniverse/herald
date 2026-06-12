package oidc

import (
	"log"
	"net/http"
)

// authorizationCodeGrant is the RFC 6749 §4.1 grant_type value.
const authorizationCodeGrant = "authorization_code"

// CodeGrant implements the authorization_code token exchange: redeem the
// single-use code, verify PKCE + client/redirect binding, and issue the same
// access(+refresh) tokens the password grant issues. Mirrors HumanGrant's
// shape. IdentityResolver already carries GetUser + IsActive, so no wider
// resolver interface is needed.
type CodeGrant struct {
	p       *Provider
	id      IdentityResolver
	codes   *CodeStore
	refresh *RefreshIssuer
}

// NewCodeGrant wires the grant.
func NewCodeGrant(p *Provider, id IdentityResolver, codes *CodeStore, refresh *RefreshIssuer) *CodeGrant {
	return &CodeGrant{p: p, id: id, codes: codes, refresh: refresh}
}

// ServeToken handles POST /token for grant_type=authorization_code. All
// rejection paths return the same "code rejected" error so probing reveals
// nothing, and Redeem-first means any failed attempt burns the code.
func (g *CodeGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	pa, ok := g.codes.Redeem(r.Form.Get("code"))
	if !ok {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "code rejected")
		return
	}
	// RFC 6749 §4.1.3: the exchange must present the same client + redirect
	// the code was issued to, and (RFC 7636) the PKCE verifier.
	if r.Form.Get("client_id") != pa.ClientID ||
		r.Form.Get("redirect_uri") != pa.RedirectURI ||
		!VerifyPKCE(pa.CodeChallenge, r.Form.Get("code_verifier")) {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "code rejected")
		return
	}
	u, err := g.id.GetUser(r.Context(), pa.UserID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "code rejected")
		return
	}
	// /authorize verified the user was active when the code was issued, but
	// GetUser does not enforce status — re-check so a block landing inside the
	// code's 60s window still bites (same guard the agent grant applies).
	if !g.id.IsActive(r.Context(), u.ID) {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "code rejected")
		return
	}
	claims, err := accessClaims(r.Context(), g.id, u)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "code rejected")
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
		// Refresh is best-effort, same posture as HumanGrant: a failure still
		// returns a usable access token, but log it.
		if rtok, err := g.refresh.Issue(r.Context(), u.ID); err != nil {
			log.Printf("oidc: refresh.Issue for authorization_code user %s: %v", u.ID, err)
		} else {
			resp["refresh_token"] = rtok
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
