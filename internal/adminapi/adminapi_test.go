package adminapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	casket "github.com/CarriedWorldUniverse/casket-go"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

const adminToken = "test-admin-token"

func newStack(t *testing.T) (*identity.Service, *herald.Provider, *httptest.Server) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)

	_, signKey, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	p, _ := herald.NewProvider(herald.Config{Issuer: srv.URL + "/", SigningKey: signKey})
	grant := herald.NewAgentGrant(p, svc)
	p.SetTokenHandler(grant)

	api := adminapi.New(svc, p, adminToken)

	// Combined mux: OIDC endpoints + admin/provision API.
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", p.Handler())
	mux.Handle("/jwks", p.Handler())
	mux.Handle("/token", p.Handler())
	mux.Handle("/api/", api.Handler())
	srv.Config.Handler = mux
	return svc, p, srv
}

func doJSON(t *testing.T, method, url, bearer string, body any) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

// mintAgentToken has an agent sign a casket assertion and exchange it at /token.
func mintAgentToken(t *testing.T, srvURL, agentID string, priv ed25519.PrivateKey) string {
	t.Helper()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": agentID, "sub": agentID, "aud": srvURL + "/token",
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	})
	obj, _ := signer.Sign(payload)
	assertion, _ := obj.CompactSerialize()
	resp, _ := http.PostForm(srvURL+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	})
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("mintAgentToken failed: %+v", body)
	}
	return tok
}

// issueHumanToken uses the admin MVP login stand-in to mint a human token.
func issueHumanToken(t *testing.T, srvURL, humanID string) string {
	t.Helper()
	resp, body := adminPost(t, srvURL+"/api/humans/"+humanID+"/token", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("issue human token: %d %+v", resp.StatusCode, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no human token: %+v", body)
	}
	return tok
}

// mintAgentTokenExpectFail attempts a token mint; returns true if it SUCCEEDED
// (used to assert a pending agent CANNOT mint).
func mintAgentTokenExpectFail(t *testing.T, srvURL, agentID string, priv ed25519.PrivateKey) bool {
	t.Helper()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": agentID, "sub": agentID, "aud": srvURL + "/token",
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	})
	obj, _ := signer.Sign(payload)
	assertion, _ := obj.CompactSerialize()
	resp, err := http.PostForm(srvURL+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	})
	if err != nil {
		t.Fatalf("mint attempt: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// TestGoldenPath exercises the operator's stated MVP loop:
// create org -> create human -> bootstrap agent -> that agent self-provisions
// a new agent under the same human -> the new agent OAuths a JWT.
func TestGoldenPath(t *testing.T) {
	svc, _, srv := newStack(t)
	ctx := context.Background()

	// admin endpoints require the admin token.
	resp, _ := doJSON(t, "POST", srv.URL+"/api/orgs", "", map[string]any{"name": "acme"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("org create without admin token should be 401, got %d", resp.StatusCode)
	}

	// 1. admin bootstrap: org.
	resp, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	if resp.StatusCode != 200 {
		t.Fatalf("create org: %d %+v", resp.StatusCode, org)
	}
	orgID, _ := org["id"].(string)

	// 2. admin bootstrap: human.
	resp, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "jacinta"})
	if resp.StatusCode != 200 {
		t.Fatalf("create human: %d %+v", resp.StatusCode, human)
	}
	humanID, _ := human["id"].(string)

	// 3. admin bootstrap: the bootstrap agent (with agent:create scope) under the human.
	bsPriv, bsPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "bootstrap")
	resp, bsAgent := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", map[string]any{
		"display_name":      "bootstrap",
		"responsible_human": humanID,
		"casket_pubkey":     base64.StdEncoding.EncodeToString(bsPub),
		"scopes":            []string{"agent:create", "repo:read"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("create bootstrap agent: %d %+v", resp.StatusCode, bsAgent)
	}
	bsID, _ := bsAgent["id"].(string)

	// 4. bootstrap agent mints its token.
	bsTok := mintAgentToken(t, srv.URL, bsID, bsPriv)

	// 5. THE SELF-PROVISION: bootstrap agent creates a NEW agent via the tool.
	_, newPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	resp, newAgent := doJSON(t, "POST", srv.URL+"/api/agents", bsTok, map[string]any{
		"display_name":  "anvil",
		"casket_pubkey": base64.StdEncoding.EncodeToString(newPub),
		"scopes":        []string{"repo:write"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("self-provision create_agent: %d %+v", resp.StatusCode, newAgent)
	}
	newID, _ := newAgent["id"].(string)
	if newID == "" {
		t.Fatalf("no new agent id: %+v", newAgent)
	}

	// The new agent's responsible human MUST be the caller's human (un-spoofable).
	got, err := svc.GetUser(ctx, newID)
	if err != nil {
		t.Fatalf("GetUser new agent: %v", err)
	}
	if got.ResponsibleHuman != humanID {
		t.Fatalf("new agent responsible_human = %q, want %q (the caller's human)", got.ResponsibleHuman, humanID)
	}
	if got.OrgID != orgID {
		t.Fatalf("new agent org = %q, want %q", got.OrgID, orgID)
	}

	// 6. HUMAN-IN-THE-LOOP: the self-provisioned agent is PENDING and cannot
	//    mint a token until a human validates it.
	if got.Status != store.StatusPending {
		t.Fatalf("self-provisioned agent should be pending, got %q", got.Status)
	}
	newPriv, _, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	if mintAgentTokenExpectFail(t, srv.URL, newID, newPriv) {
		t.Fatal("pending agent must NOT be able to mint a token")
	}

	// Human gets a token (MVP login stand-in) and validates the agent.
	humanTok := issueHumanToken(t, srv.URL, humanID)
	resp, vbody := doJSON(t, "POST", srv.URL+"/api/agents/"+newID+"/validate", humanTok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("validate: %d %+v", resp.StatusCode, vbody)
	}

	// Now the validated agent CAN mint.
	tok := mintAgentToken(t, srv.URL, newID, newPriv)
	if tok == "" {
		t.Fatal("validated agent should be able to mint")
	}
}

func TestValidate_OnlyResponsibleHuman(t *testing.T) {
	svc, _, srv := newStack(t)
	ctx := context.Background()
	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)
	_, h1 := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "jacinta"})
	h1ID, _ := h1["id"].(string)
	_, h2 := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "other"})
	h2ID, _ := h2["id"].(string)

	// Pending agent under h1.
	_, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "pend")
	ag, _ := svc.CreateAgentPending(ctx, orgID, "pend", h1ID, pub)

	// h2 (not the responsible human) must NOT be able to validate.
	h2Tok := issueHumanToken(t, srv.URL, h2ID)
	resp, _ := doJSON(t, "POST", srv.URL+"/api/agents/"+ag.ID+"/validate", h2Tok, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-responsible human validate should be 403, got %d", resp.StatusCode)
	}
}

func TestSelfProvision_RequiresAgentCreateScope(t *testing.T) {
	_, _, srv := newStack(t)

	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)
	_, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "jacinta"})
	humanID, _ := human["id"].(string)

	// Agent WITHOUT agent:create scope.
	priv, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "weak")
	_, weak := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", map[string]any{
		"display_name":      "weak",
		"responsible_human": humanID,
		"casket_pubkey":     base64.StdEncoding.EncodeToString(pub),
		"scopes":            []string{"repo:read"}, // no agent:create
	})
	weakID, _ := weak["id"].(string)
	tok := mintAgentToken(t, srv.URL, weakID, priv)

	_, newPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "child")
	resp, _ := doJSON(t, "POST", srv.URL+"/api/agents", tok, map[string]any{
		"display_name":  "child",
		"casket_pubkey": base64.StdEncoding.EncodeToString(newPub),
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("self-provision without agent:create should be 403, got %d", resp.StatusCode)
	}
}

func TestSelfProvision_RequiresToken(t *testing.T) {
	_, _, srv := newStack(t)
	resp, _ := doJSON(t, "POST", srv.URL+"/api/agents", "", map[string]any{"display_name": "x"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("self-provision without token should be 401, got %d", resp.StatusCode)
	}
}

// adminPost is a doJSON with the admin bearer token.
func adminPost(t *testing.T, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	return doJSON(t, "POST", url, adminToken, body)
}

func TestAgentByFingerprint(t *testing.T) {
	_, _, srv := newStack(t)

	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)
	_, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "jacinta"})
	humanID, _ := human["id"].(string)

	_, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	_, agent := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", map[string]any{
		"display_name":      "anvil",
		"responsible_human": humanID,
		"casket_pubkey":     base64.StdEncoding.EncodeToString(pub),
		"scopes":            []string{"repo:read", "repo:write"},
	})
	agentID, _ := agent["id"].(string)
	fp, _ := agent["fingerprint"].(string)
	if fp == "" {
		t.Fatalf("agent create returned no fingerprint: %+v", agent)
	}

	// Resolve by fingerprint (admin-gated GET).
	resp, got := doJSON(t, "GET", srv.URL+"/api/agents/by-fingerprint/"+fp, adminToken, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("by-fingerprint: %d %+v", resp.StatusCode, got)
	}
	if got["id"] != agentID {
		t.Fatalf("id = %v, want %q", got["id"], agentID)
	}
	if got["kind"] != "agent" {
		t.Fatalf("kind = %v, want agent", got["kind"])
	}
	if got["fingerprint"] != fp {
		t.Fatalf("fingerprint = %v, want %q", got["fingerprint"], fp)
	}
	if got["responsible_human"] != humanID {
		t.Fatalf("responsible_human = %v, want %q", got["responsible_human"], humanID)
	}
	scopes, _ := got["scopes"].([]any)
	if len(scopes) != 2 {
		t.Fatalf("scopes = %v, want repo:read + repo:write", got["scopes"])
	}
	if got["active"] != true {
		t.Fatalf("active = %v, want true", got["active"])
	}

	// Unknown fingerprint -> 404.
	resp, _ = doJSON(t, "GET", srv.URL+"/api/agents/by-fingerprint/nope-nope-nope", adminToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown fingerprint status = %d, want 404", resp.StatusCode)
	}

	// In-cluster service lookup: NOT admin-gated (cairn resolves a pubkey
	// without the admin token). No-token still resolves — the network is the
	// access control. It is NOT a gateway public-path, so external callers
	// still hit the gateway's bearer auth; only in-cluster services reach
	// this unauthenticated (intra-cluster-trust posture, tightened to mesh
	// mTLS / a scoped service token later).
	resp, _ = doJSON(t, "GET", srv.URL+"/api/agents/by-fingerprint/"+fp, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no-token in-cluster lookup = %d, want 200", resp.StatusCode)
	}
}
