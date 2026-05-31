// Package adminapi exposes herald's provisioning surface:
//
//   - Admin-bootstrap endpoints (static admin-token gated) to create the first
//     org, humans, and agents — solving the chicken-and-egg (you need a human
//     before a human-held token can provision).
//   - The SELF-PROVISION tool: POST /api/agents, authenticated by a herald
//     token. An actor holding a human's (or an agent-with-agent:create's) token
//     creates a new agent; the new agent's responsible_human is taken FROM THE
//     CALLER'S VERIFIED TOKEN, never from client input (un-spoofable). This is
//     the "agent uses a tool to create its own agent account" flow.
//
// MVP scope: see the herald MVP spec §2 + the self-provision refinement.
package adminapi

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ScopeAgentCreate is the capability required to self-provision new agents.
const ScopeAgentCreate = "agent:create"

// Identity is the subset of identity.Service adminapi needs.
type Identity interface {
	CreateOrg(ctx context.Context, name string) (store.Org, error)
	CreateHuman(ctx context.Context, orgID, displayName string) (store.User, error)
	CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	CreateAgentPending(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error)
	ValidateAgent(ctx context.Context, agentID, validatingHuman string) error
	GrantScope(ctx context.Context, userID, scope, grantedBy string) error
	GetUser(ctx context.Context, id string) (store.User, error)
	GetAgentByFingerprint(ctx context.Context, fp string) (store.User, error)
	EffectiveScopes(ctx context.Context, userID string) ([]string, error)
}

// TokenIssuer verifies herald tokens and signs new ones. The provider
// satisfies both (VerifyToken / SignToken).
type TokenIssuer interface {
	VerifyToken(token string) (map[string]any, error)
	SignToken(claims map[string]any) (string, error)
}

// TokenVerifier is the read-only subset (kept for back-compat in signatures).
type TokenVerifier = TokenIssuer

// API is the provisioning HTTP surface.
type API struct {
	id         Identity
	tokens     TokenIssuer
	adminToken string
}

// New builds the API. adminToken gates the bootstrap endpoints.
func New(id Identity, tokens TokenIssuer, adminToken string) *API {
	return &API{id: id, tokens: tokens, adminToken: adminToken}
}

// Handler returns the provisioning mux.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	// Admin bootstrap (static admin token).
	mux.HandleFunc("POST /api/orgs", a.adminOnly(a.handleCreateOrg))
	mux.HandleFunc("POST /api/orgs/{org}/humans", a.adminOnly(a.handleCreateHuman))
	mux.HandleFunc("POST /api/orgs/{org}/agents", a.adminOnly(a.handleAdminCreateAgent))
	// NEX-412: resolve an agent by its casket fingerprint — cairn's SSH ingress
	// maps an incoming pubkey to a herald agent. Admin-gated read.
	mux.HandleFunc("GET /api/agents/by-fingerprint/{fp}", a.adminOnly(a.handleAgentByFingerprint))
	// MVP human "login" stand-in: admin mints a human token. Full passkey/
	// password login is deferred (spec §9); this gives humans a token so they
	// can validate agents + self-provision now.
	mux.HandleFunc("POST /api/humans/{id}/token", a.adminOnly(a.handleIssueHumanToken))
	// Self-provision tool (herald token, agent:create scope) — creates PENDING.
	mux.HandleFunc("POST /api/agents", a.handleSelfProvisionAgent)
	// Human validates a pending agent (human token; must be the responsible human).
	mux.HandleFunc("POST /api/agents/{id}/validate", a.handleValidateAgent)
	return mux
}

// --- admin bootstrap ---

func (a *API) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	org, err := a.id.CreateOrg(r.Context(), body.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": org.ID, "name": org.Name})
}

func (a *API) handleCreateHuman(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("org")
	var body struct {
		DisplayName string `json:"display_name"`
	}
	if !decode(w, r, &body) {
		return
	}
	h, err := a.id.CreateHuman(r.Context(), orgID, body.DisplayName)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": h.ID, "display_name": h.DisplayName, "org": h.OrgID})
}

// handleAdminCreateAgent is the bootstrap path: admin creates an agent under a
// named human, with an explicit scope list. Used to mint the first
// (bootstrap) agent before any agent token exists.
func (a *API) handleAdminCreateAgent(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("org")
	var body agentBody
	if !decode(w, r, &body) {
		return
	}
	if body.ResponsibleHuman == "" {
		writeErr(w, http.StatusBadRequest, "responsible_human required")
		return
	}
	// Admin-bootstrap agents are created ACTIVE (they predate any human token
	// that could validate them — the chicken-and-egg root).
	a.createAgent(w, r.Context(), orgID, body.ResponsibleHuman, body, false)
}

// handleIssueHumanToken mints a herald token for a human (MVP login stand-in,
// admin-gated). The token carries kind=human, the human's org, and their
// granted scopes — so a human can validate agents + self-provision.
func (a *API) handleIssueHumanToken(w http.ResponseWriter, r *http.Request) {
	humanID := r.PathValue("id")
	human, err := a.id.GetUser(r.Context(), humanID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "human not found")
		return
	}
	if human.Kind != store.KindHuman {
		writeErr(w, http.StatusBadRequest, "not a human")
		return
	}
	scopes, _ := a.id.EffectiveScopes(r.Context(), humanID)
	claims := map[string]any{
		"sub":   human.ID,
		"kind":  string(store.KindHuman),
		"org":   human.OrgID,
		"scope": joinFields(scopes),
	}
	if human.CasketFingerprint != "" {
		claims["human_fp"] = human.CasketFingerprint
	}
	tok, err := a.tokens.SignToken(claims)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sign failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer"})
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

// createAgent is shared by the admin + self-provision paths: decode pubkey,
// create the agent (pending or active), grant requested scopes (granter = the
// responsible human).
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
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, sc := range body.Scopes {
		if err := a.id.GrantScope(ctx, agent.ID, sc, responsibleHuman); err != nil {
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
		"scopes":            scopes,
	})
}

// --- helpers ---

type agentBody struct {
	DisplayName      string   `json:"display_name"`
	ResponsibleHuman string   `json:"responsible_human"` // admin path only; ignored on self-provision
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

func (a *API) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.adminToken)) != 1 {
			writeErr(w, http.StatusUnauthorized, "admin token required")
			return
		}
		next(w, r)
	}
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

func joinFields(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
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
