package oidc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// jwtBearerGrant is the RFC 7523 grant type agents use.
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// IdentityResolver is the slice of the identity service the agent grant needs.
// Kept as an interface so the grant is testable + decoupled from the concrete
// service.
type IdentityResolver interface {
	GetUser(ctx context.Context, id string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
	IsActive(ctx context.Context, id string) bool
}

// AgentGrant implements the casket jwt-bearer token endpoint: an agent signs a
// JWT assertion with its casket Ed25519 key; herald verifies it against the
// agent's REGISTERED public key, enforces the block cascade, and issues a
// short-lived access token whose claims (incl. act.sub = responsible human)
// are stamped FROM THE RECORD — never from client input.
type AgentGrant struct {
	p  *Provider
	id IdentityResolver
}

// NewAgentGrant wires the grant to a provider + identity resolver.
func NewAgentGrant(p *Provider, id IdentityResolver) *AgentGrant {
	return &AgentGrant{p: p, id: id}
}

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

	tok, err := g.issue(r.Context(), assertion, g.p.TokenURL())
	if err != nil {
		// Uniform 401 for all assertion failures — don't leak which check failed.
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "assertion rejected")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(g.p.TTL().Seconds()),
	})
}

// issue verifies the assertion and returns a signed access token, or an error
// (deliberately coarse — the handler maps any error to 401).
func (g *AgentGrant) issue(ctx context.Context, assertion, tokenURL string) (string, error) {
	// 1. Parse the assertion WITHOUT trusting it (no key yet) to read `sub`.
	jws, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return "", fmt.Errorf("parse assertion: %w", err)
	}
	var unverified assertionClaims
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return "", fmt.Errorf("assertion claims: %w", err)
	}
	if unverified.Subject == "" || unverified.Issuer != unverified.Subject {
		return "", errors.New("assertion iss must equal sub (the agent id)")
	}

	// 2. Resolve the agent + its REGISTERED casket public key.
	agent, err := g.id.GetUser(ctx, unverified.Subject)
	if err != nil {
		return "", fmt.Errorf("unknown agent: %w", err)
	}
	if agent.Kind != store.KindAgent || len(agent.CasketPubkey) != ed25519.PublicKeySize {
		return "", errors.New("subject is not a key-registered agent")
	}

	// 3. Verify the assertion signature against the registered key. This is the
	//    proof-of-possession: only the holder of the agent's casket private key
	//    can produce a valid assertion.
	verified, err := jws.Verify(ed25519.PublicKey(agent.CasketPubkey))
	if err != nil {
		return "", fmt.Errorf("assertion signature: %w", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(verified, &claims); err != nil {
		return "", fmt.Errorf("verified claims: %w", err)
	}

	// 4. Validate audience + expiry of the assertion.
	if !claims.audienceMatches(tokenURL) {
		return "", errors.New("assertion audience mismatch")
	}
	if claims.Expiry == 0 || g.p.Now().After(time.Unix(claims.Expiry, 0)) {
		return "", errors.New("assertion expired or missing exp")
	}

	// 5. Enforce the block cascade — agent must be active AND its responsible
	//    human + org must be active (identity.IsActive evaluates this).
	if !g.id.IsActive(ctx, agent.ID) {
		return "", errors.New("agent inactive (blocked, or responsible human/org blocked)")
	}

	// 6. Assemble the access token. act.sub, org, fingerprints come FROM THE
	//    RECORD — client-supplied values in the assertion are ignored.
	scopes, err := g.id.EffectiveScopes(ctx, agent.ID)
	if err != nil {
		return "", fmt.Errorf("scopes: %w", err)
	}
	out := map[string]any{
		"sub":      agent.ID,
		"kind":     string(store.KindAgent),
		"org":      agent.OrgID,
		"scope":    strings.Join(scopes, " "),
		"agent_fp": agent.CasketFingerprint,
	}
	if agent.ResponsibleHuman != "" {
		out["act"] = map[string]any{"sub": agent.ResponsibleHuman}
		if human, err := g.id.GetUser(ctx, agent.ResponsibleHuman); err == nil && human.CasketFingerprint != "" {
			out["human_fp"] = human.CasketFingerprint
		}
	}
	return g.p.SignToken(out)
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
