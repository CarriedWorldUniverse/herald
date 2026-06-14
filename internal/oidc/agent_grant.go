package oidc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// jwtBearerGrant is the RFC 7523 grant type agents use.
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// idJAGType is the auth.md / RFC 8693 identity-assertion grant token type.
const idJAGType = "urn:ietf:params:oauth:token-type:id-jag"

// IdentityResolver is the slice of the identity service the agent grant needs.
// Kept as an interface so the grant is testable + decoupled from the concrete
// service.
type IdentityResolver interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
	IsActive(ctx context.Context, id string) bool
	EnabledProducts(ctx context.Context, orgID string) ([]string, error)
}

// AgentGrant implements the casket jwt-bearer token endpoint: an agent signs a
// JWT assertion with its casket Ed25519 key; herald verifies it against the
// agent's REGISTERED public key, enforces the block cascade, and issues a
// short-lived access token whose claims (incl. act.sub = responsible human)
// are stamped FROM THE RECORD — never from client input.
type AgentGrant struct {
	p        *Provider
	id       IdentityResolver
	refresh  *RefreshIssuer
	idjagTTL time.Duration
}

// NewAgentGrant wires the grant to a provider + identity resolver.
func NewAgentGrant(p *Provider, id IdentityResolver, refresh *RefreshIssuer) *AgentGrant {
	return &AgentGrant{p: p, id: id, refresh: refresh, idjagTTL: 5 * time.Minute}
}

// SetIDJAGTTL overrides the lifetime of minted ID-JAGs (default 5m).
func (g *AgentGrant) SetIDJAGTTL(d time.Duration) { g.idjagTTL = d }

// ServeToken handles POST /token for the jwt-bearer grant.
func (g *AgentGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	if r.Form.Get("grant_type") != jwtBearerGrant {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only jwt-bearer is supported")
		return
	}
	assertion := r.Form.Get("assertion")
	if assertion == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing assertion")
		return
	}

	tok, subject, err := g.issue(r.Context(), assertion, g.p.TokenURL())
	if err != nil {
		// Uniform 401 for all assertion failures — don't leak which check failed.
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "assertion rejected")
		return
	}
	resp := map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	}
	if g.refresh != nil {
		// Refresh is best-effort: a failure still returns a usable access token,
		// but log it — silent absence would surface only as clients re-minting.
		if rtok, err := g.refresh.Issue(r.Context(), subject); err != nil {
			log.Printf("oidc: refresh.Issue for agent %s: %v", subject, err)
		} else {
			resp["refresh_token"] = rtok
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// verifyAssertion validates an agent's casket-signed jwt-bearer assertion
// against the registered key + block cascade and returns the agent record.
// wantAud is the canonical endpoint URL the assertion's `aud` must match
// (issuer+"/token" for the token endpoint, issuer+"/agent/identity" for the
// identity endpoint) — never r.Host, so it is proxy-safe.
func (g *AgentGrant) verifyAssertion(ctx context.Context, assertion, wantAud string) (store.User, error) {
	// 1. Parse the assertion WITHOUT trusting it (no key yet) to read `sub`.
	jws, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return store.User{}, fmt.Errorf("parse assertion: %w", err)
	}
	var unverified assertionClaims
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return store.User{}, fmt.Errorf("assertion claims: %w", err)
	}
	if unverified.Subject == "" || unverified.Issuer != unverified.Subject {
		return store.User{}, errors.New("assertion iss must equal sub (the agent id)")
	}

	// 2. Resolve the agent + its REGISTERED casket public key.
	agent, err := g.id.GetUser(ctx, unverified.Subject)
	if err != nil {
		return store.User{}, fmt.Errorf("unknown agent: %w", err)
	}
	if agent.Kind != store.KindAgent || len(agent.CasketPubkey) != ed25519.PublicKeySize {
		return store.User{}, errors.New("subject is not a key-registered agent")
	}

	// 3. Verify the assertion signature against the registered key. This is the
	//    proof-of-possession: only the holder of the agent's casket private key
	//    can produce a valid assertion.
	verified, err := jws.Verify(ed25519.PublicKey(agent.CasketPubkey))
	if err != nil {
		return store.User{}, fmt.Errorf("assertion signature: %w", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(verified, &claims); err != nil {
		return store.User{}, fmt.Errorf("verified claims: %w", err)
	}

	// 4. Validate audience + expiry of the assertion.
	if !claims.audienceMatches(wantAud) {
		return store.User{}, errors.New("assertion audience mismatch")
	}
	if claims.Expiry == 0 || g.p.Now().After(time.Unix(claims.Expiry, 0)) {
		return store.User{}, errors.New("assertion expired or missing exp")
	}

	// 5. Enforce the block cascade — agent must be active AND its responsible
	//    human + org must be active (identity.IsActive evaluates this).
	if !g.id.IsActive(ctx, agent.ID) {
		return store.User{}, errors.New("agent inactive (blocked, or responsible human/org blocked)")
	}
	return agent, nil
}

// issue verifies the assertion and returns a signed general access token (the
// jwt-bearer /token path). The handler maps any error to a uniform 401.
func (g *AgentGrant) issue(ctx context.Context, assertion, tokenURL string) (token, subject string, err error) {
	agent, err := g.verifyAssertion(ctx, assertion, tokenURL)
	if err != nil {
		return "", "", err
	}
	// Claims come FROM THE RECORD — client-supplied values are ignored.
	out, err := accessClaims(ctx, g.id, agent)
	if err != nil {
		return "", "", fmt.Errorf("claims: %w", err)
	}
	signed, err := g.p.SignToken(out)
	if err != nil {
		return "", "", err
	}
	return signed, agent.ID, nil
}

// randomJTI returns a 128-bit base64url replay nonce.
func randomJTI() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// mintIDJAG builds an audience-scoped ID-JAG for the given agent. Claims come
// FROM THE RECORD (sub/org/act.sub/scope/products via accessClaims) plus the
// requested audience, a fresh jti, and client_id. Signed short-lived.
func (g *AgentGrant) mintIDJAG(ctx context.Context, agent store.User, audience string) (string, error) {
	out, err := accessClaims(ctx, g.id, agent)
	if err != nil {
		return "", fmt.Errorf("claims: %w", err)
	}
	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("jti: %w", err)
	}
	out["aud"] = audience
	out["jti"] = jti
	out["client_id"] = agent.ID
	return g.p.SignShortLived(out, g.idjagTTL)
}

// ServeIdentity handles POST /agent/identity — the auth.md identity endpoint.
// For type=identity_assertion the agent presents a self-signed proof-of-
// possession assertion (aud = this endpoint) plus the target service
// `audience`; herald returns an audience-scoped ID-JAG.
func (g *AgentGrant) ServeIdentity(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	if r.Form.Get("type") != "identity_assertion" {
		oauthError(w, http.StatusBadRequest, "unsupported_identity_type", "only identity_assertion is supported")
		return
	}
	assertion := r.Form.Get("assertion")
	audience := r.Form.Get("audience")
	if assertion == "" || audience == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "assertion and audience are required")
		return
	}
	agent, err := g.verifyAssertion(r.Context(), assertion, g.p.IdentityURL())
	if err != nil {
		// Uniform 401 — don't leak which check failed.
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "assertion rejected")
		return
	}
	idjag, err := g.mintIDJAG(r.Context(), agent, audience)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "mint failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      idjag,
		"issued_token_type": idJAGType,
		"token_type":        "N_A",
		"expires_in":        int(g.idjagTTL.Seconds()),
	})
}

// assertionClaims is the subset of the agent's jwt-bearer assertion herald reads.
type assertionClaims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience any    `json:"aud"` // string or []string per JWT spec
	Expiry   int64  `json:"exp"`
}

func (c assertionClaims) audienceMatches(want string) bool {
	switch a := c.Audience.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == want {
				return true
			}
		}
	}
	return false
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]any{"error": code, "error_description": desc})
}
