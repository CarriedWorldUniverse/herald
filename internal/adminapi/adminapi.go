// Package adminapi exposes herald's token-authenticated HTTP surface:
//
//   - The SELF-PROVISION tool: POST /api/agents, authenticated by a herald
//     token. An actor holding a human's (or an agent-with-agent:create's) token
//     creates a new agent; the new agent's responsible_human is taken FROM THE
//     CALLER'S VERIFIED TOKEN, never from client input (un-spoofable). This is
//     the "agent uses a tool to create its own agent account" flow.
//   - Agent validation: POST /api/agents/{id}/validate (human token).
//   - by-fingerprint lookup: GET /api/agents/by-fingerprint/{fp}, an in-cluster
//     service lookup for cairn's SSH ingress.
//
// The org/human/agent ADMIN provisioning surface moved to the gRPC AdminService
// (internal/grpcadmin), fronted by interchange with identity-derived authz —
// the static admin token it used to carry is retired. This package keeps only
// the token-authed flows that are NOT admin operations.
//
// MVP scope: see the herald MVP spec §2 + the self-provision refinement.
package adminapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ScopeAgentCreate is the capability required to self-provision new agents.
const ScopeAgentCreate = "agent:create"

// Identity is the subset of identity.Service adminapi needs. (Org/human/product
// admin operations live in the gRPC AdminService now and are not listed here.)
type Identity interface {
	CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	CreateAgentPending(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	ValidateAgent(ctx context.Context, agentID, validatingHuman string) error
	GrantScope(ctx context.Context, userID, scope, grantedBy string) error
	GetAgentByFingerprint(ctx context.Context, fp string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
}

// TokenVerifier verifies herald tokens (the self-provision + validate flows
// derive the caller's identity from a verified token). The OIDC provider
// satisfies it.
type TokenVerifier interface {
	VerifyToken(token string) (map[string]any, error)
}

// API is the token-authenticated provisioning HTTP surface.
type API struct {
	id     Identity
	tokens TokenVerifier
}

// New builds the API.
func New(id Identity, tokens TokenVerifier) *API {
	return &API{id: id, tokens: tokens}
}

// Handler returns the provisioning mux. Every route here is either token-authed
// (self-provision, validate) or an in-cluster service lookup (by-fingerprint);
// none is gated by a static admin token.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	// NEX-412: resolve an agent by its casket fingerprint — cairn's SSH ingress
	// maps an incoming pubkey to a herald agent. NOT admin-gated: this is an
	// in-cluster SERVICE lookup (cairn → herald.cwb.svc). It is NOT a gateway
	// public-path, so external callers still hit the gateway's bearer-auth; only
	// in-cluster services reach it unauthenticated (the intra-cluster-trust
	// posture — tightened to mesh-mTLS / a scoped service token later). It
	// returns only id/org/scopes/status. (cairn now prefers the gRPC
	// AgentService over mTLS; this HTTP form remains for non-gRPC callers.)
	mux.HandleFunc("GET /api/agents/by-fingerprint/{fp}", a.handleAgentByFingerprint)
	// Self-provision tool (herald token, agent:create scope) — creates PENDING.
	mux.HandleFunc("POST /api/agents", a.handleSelfProvisionAgent)
	// Human validates a pending agent (human token; must be the responsible human).
	mux.HandleFunc("POST /api/agents/{id}/validate", a.handleValidateAgent)
	return mux
}

// --- self-provision tool ---

// handleSelfProvisionAgent is the "agent uses a tool to create its own agent
// account" flow. The caller presents a herald token; the new agent's org +
// responsible_human are derived FROM THAT TOKEN (un-spoofable), not the body.
func (a *API) handleSelfProvisionAgent(w http.ResponseWriter, r *http.Request) {
	claims, err := a.verifyBearer(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "valid herald token required")
		return
	}
	// Must hold the agent:create scope.
	if !claimsHaveScope(claims, ScopeAgentCreate) {
		writeErr(w, http.StatusForbidden, "agent:create scope required")
		return
	}

	callerOrg, _ := claims["org"].(string)
	callerSub, _ := claims["sub"].(string)
	callerKind, _ := claims["kind"].(string)

	// The responsible human for the new agent:
	//   - caller is a human  -> the caller themselves.
	//   - caller is an agent -> the caller's own responsible human (act.sub),
	//     so a provisioned sibling answers to the same human (one level; MVP).
	responsibleHuman := callerSub
	if callerKind == string(store.KindAgent) {
		if act, ok := claims["act"].(map[string]any); ok {
			if sub, _ := act["sub"].(string); sub != "" {
				responsibleHuman = sub
			}
		}
	}
	if callerOrg == "" || responsibleHuman == "" {
		writeErr(w, http.StatusBadRequest, "caller token missing org/responsible human")
		return
	}

	var body agentBody
	if !decode(w, r, &body) {
		return
	}
	// Self-provisioned agents land PENDING — a human must validate before the
	// agent can authenticate (human-in-the-loop at account birth).
	a.createAgent(w, r.Context(), callerOrg, responsibleHuman, body, true)
}

// handleValidateAgent flips a pending self-provisioned agent to active. The
// caller must present a HUMAN herald token, and must be the agent's
// responsible human (enforced in identity.ValidateAgent).
func (a *API) handleValidateAgent(w http.ResponseWriter, r *http.Request) {
	claims, err := a.verifyBearer(r)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "valid herald token required")
		return
	}
	if kind, _ := claims["kind"].(string); kind != string(store.KindHuman) {
		writeErr(w, http.StatusForbidden, "only a human may validate an agent")
		return
	}
	humanID, _ := claims["sub"].(string)
	agentID := r.PathValue("id")
	if err := a.id.ValidateAgent(r.Context(), agentID, humanID); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": agentID, "status": "active"})
}

// createAgent decodes the pubkey, creates the agent (pending or active), and
// grants requested scopes (granter = the responsible human).
func (a *API) createAgent(w http.ResponseWriter, ctx context.Context, orgID, responsibleHuman string, body agentBody, pending bool) {
	pub, err := body.pubkey()
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	create := a.id.CreateAgent
	if pending {
		create = a.id.CreateAgentPending
	}
	agent, err := create(ctx, orgID, body.DisplayName, responsibleHuman, pub)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateFingerprint) {
			writeErr(w, http.StatusConflict, "casket pubkey already registered")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	expanded, err := identity.ExpandScopes(body.Scopes)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, sc := range expanded {
		if err := a.id.GrantScope(ctx, agent.ID, sc, responsibleHuman); err != nil {
			if errors.Is(err, identity.ErrControlPlaneScopeForTenant) {
				writeErr(w, http.StatusForbidden, err.Error())
				return
			}
			writeErr(w, http.StatusInternalServerError, "scope grant failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                agent.ID,
		"display_name":      agent.DisplayName,
		"org":               agent.OrgID,
		"responsible_human": agent.ResponsibleHuman,
		"fingerprint":       agent.CasketFingerprint,
		"status":            string(agent.Status),
		"scopes":            body.Scopes,
	})
}

// handleAgentByFingerprint resolves an agent from its casket fingerprint
// (NEX-412). cairn's SSH ingress computes the fingerprint of an incoming
// public key and asks herald "which agent is this?". Returns the agent
// projection + effective scopes; 404 if no agent has that fingerprint.
func (a *API) handleAgentByFingerprint(w http.ResponseWriter, r *http.Request) {
	fp := r.PathValue("fp")
	if fp == "" {
		writeErr(w, http.StatusBadRequest, "fingerprint required")
		return
	}
	agent, err := a.id.GetAgentByFingerprint(r.Context(), fp)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no agent for fingerprint")
		return
	}
	if agent.Kind != store.KindAgent {
		writeErr(w, http.StatusNotFound, "no agent for fingerprint")
		return
	}
	scopes, err := a.id.EffectiveScopes(r.Context(), agent.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "scopes lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                agent.ID,
		"kind":              string(agent.Kind),
		"display_name":      agent.DisplayName,
		"org":               agent.OrgID,
		"responsible_human": agent.ResponsibleHuman,
		"fingerprint":       agent.CasketFingerprint,
		"status":            string(agent.Status),
		"active":            agent.Status == store.StatusActive,
		"scopes":            scopes,
	})
}

// --- helpers ---

type agentBody struct {
	DisplayName      string   `json:"display_name"`
	ResponsibleHuman string   `json:"responsible_human"` // ignored on self-provision (derived from token)
	CasketPubkey     string   `json:"casket_pubkey"`     // base64 (std)
	Scopes           []string `json:"scopes"`
}

func (b agentBody) pubkey() (ed25519.PublicKey, error) {
	if b.DisplayName == "" {
		return nil, errors.New("display_name required")
	}
	raw, err := base64.StdEncoding.DecodeString(b.CasketPubkey)
	if err != nil {
		return nil, errors.New("casket_pubkey must be base64")
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("casket_pubkey must be a 32-byte ed25519 key")
	}
	return ed25519.PublicKey(raw), nil
}

func (a *API) verifyBearer(r *http.Request) (map[string]any, error) {
	tok := bearer(r)
	if tok == "" {
		return nil, errors.New("no bearer token")
	}
	return a.tokens.VerifyToken(tok)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && h[:7] == "Bearer " {
		return h[7:]
	}
	return ""
}

func claimsHaveScope(claims map[string]any, want string) bool {
	scope, _ := claims["scope"].(string)
	for _, s := range splitFields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

func splitFields(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		writeErr(w, http.StatusBadRequest, "body required")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
