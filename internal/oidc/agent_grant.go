package oidc

import (
	"context"
	"crypto/ed25519"
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
	p       *Provider
	id      IdentityResolver
	refresh *RefreshIssuer
}

// NewAgentGrant wires the grant to a provider + identity resolver.
func NewAgentGrant(p *Provider, id IdentityResolver, refresh *RefreshIssuer) *AgentGrant {
	return &AgentGrant{p: p, id: id, refresh: refresh}
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

// issue verifies the assertion and returns a signed access token, or an error
// (deliberately coarse — the handler maps any error to 401).
func (g *AgentGrant) issue(ctx context.Context, assertion, tokenURL string) (token, subject string, err error) {
	// 1. Parse the assertion WITHOUT trusting it (no key yet) to read `sub`.
	jws, err := jose.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return "", "", fmt.Errorf("parse assertion: %w", err)
	}
	var unverified assertionClaims
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &unverified); err != nil {
		return "", "", fmt.Errorf("assertion claims: %w", err)
	}
	if unverified.Subject == "" || unverified.Issuer != unverified.Subject {
		return "", "", errors.New("assertion iss must equal sub (the agent id)")
	}

	// 2. Resolve the agent + its REGISTERED casket public key.
	agent, err := g.id.GetUser(ctx, unverified.Subject)
	if err != nil {
		return "", "", fmt.Errorf("unknown agent: %w", err)
	}
	if agent.Kind != store.KindAgent || len(agent.CasketPubkey) != ed25519.PublicKeySize {
		return "", "", errors.New("subject is not a key-registered agent")
	}

	// 3. Verify the assertion signature against the registered key. This is the
	//    proof-of-possession: only the holder of the agent's casket private key
	//    can produce a valid assertion.
	verified, err := jws.Verify(ed25519.PublicKey(agent.CasketPubkey))
	if err != nil {
		return "", "", fmt.Errorf("assertion signature: %w", err)
	}
	var claims assertionClaims
	if err := json.Unmarshal(verified, &claims); err != nil {
		return "", "", fmt.Errorf("verified claims: %w", err)
	}

	// 4. Validate audience + expiry of the assertion.
	if !claims.audienceMatches(tokenURL) {
		return "", "", errors.New("assertion audience mismatch")
	}
	if claims.Expiry == 0 || g.p.Now().After(time.Unix(claims.Expiry, 0)) {
		return "", "", errors.New("assertion expired or missing exp")
	}

	// 5. Enforce the block cascade — agent must be active AND its responsible
	//    human + org must be active (identity.IsActive evaluates this).
	if !g.id.IsActive(ctx, agent.ID) {
		return "", "", errors.New("agent inactive (blocked, or responsible human/org blocked)")
	}

	// 6. Assemble the access token. act.sub, org, fingerprints come FROM THE
	//    RECORD — client-supplied values in the assertion are ignored.
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
