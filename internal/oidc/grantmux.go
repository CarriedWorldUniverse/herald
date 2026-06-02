package oidc

import "net/http"

// GrantMux is the POST /token entry point: it routes by grant_type to the agent
// (jwt-bearer) or human (password) grant. Each grant remains a focused unit.
type GrantMux struct {
	agent   TokenHandler
	human   TokenHandler
	refresh TokenHandler
}

// NewGrantMux wires the dispatcher. All args implement TokenHandler.
func NewGrantMux(agent, human, refresh TokenHandler) *GrantMux {
	return &GrantMux{agent: agent, human: human, refresh: refresh}
}

// ServeToken dispatches on grant_type. Parsing here is harmless even though the
// delegate re-parses (ParseForm is idempotent).
func (m *GrantMux) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	switch r.Form.Get("grant_type") {
	case jwtBearerGrant:
		m.agent.ServeToken(w, r)
	case passwordGrant:
		m.human.ServeToken(w, r)
	case refreshTokenGrant:
		m.refresh.ServeToken(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type not supported")
	}
}
