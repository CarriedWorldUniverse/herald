package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	casket "github.com/CarriedWorldUniverse/casket-go"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// --- Task 4: provider primitives -------------------------------------------

func TestProvider_SignShortLived_StampsShortExpAndPreservesAud(t *testing.T) {
	p := newTestProvider(t)
	tok, err := p.SignShortLived(map[string]any{
		"sub": "agent:anvil", "aud": "ledger", "jti": "j1",
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("SignShortLived: %v", err)
	}
	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["aud"] != "ledger" || claims["jti"] != "j1" {
		t.Fatalf("aud/jti not preserved: %+v", claims)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if d := exp - iat; d < 1 || d > 60 {
		t.Fatalf("short exp expected ~30s, got exp-iat=%v", d)
	}
}

func TestProvider_IdentityURL(t *testing.T) {
	p := newTestProvider(t) // issuer "https://herald.test/"
	if got := p.IdentityURL(); got != "https://herald.test/agent/identity" {
		t.Fatalf("IdentityURL = %q", got)
	}
}

// --- Task 5: ID-JAG mint via /agent/identity -------------------------------

// testStackWithIdentity is like testStack but also wires /agent/identity.
func testStackWithIdentity(t *testing.T) (*herald.Provider, *identity.Service, *httptest.Server, *herald.AgentGrant) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	_, priv, _ := ed25519.GenerateKey(nil)
	p, err := herald.NewProvider(herald.Config{Issuer: "https://herald.test/", SigningKey: priv})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	ag := herald.NewAgentGrant(p, svc, nil)
	p.SetTokenHandler(ag)
	p.SetIdentityHandler(http.HandlerFunc(ag.ServeIdentity))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, svc, srv, ag
}

func postIdentity(t *testing.T, identityURL, assertion, audience string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"type":      {"identity_assertion"},
		"assertion": {assertion},
		"audience":  {audience},
	}
	resp, err := http.PostForm(identityURL, form)
	if err != nil {
		t.Fatalf("POST /agent/identity: %v", err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	return resp, body
}

func TestAgentIdentity_MintsConformantIDJAG(t *testing.T) {
	p, svc, srv, _ := testStackWithIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)

	// The assertion's aud is the IDENTITY endpoint (not /token).
	assertion := signAssertion(t, a.ID, p.IdentityURL(), priv, time.Now().Add(2*time.Minute))
	resp, body := postIdentity(t, srv.URL+"/agent/identity", assertion, "ledger")
	if resp.StatusCode != 200 {
		t.Fatalf("identity status=%d body=%+v", resp.StatusCode, body)
	}
	if body["issued_token_type"] != "urn:ietf:params:oauth:token-type:id-jag" {
		t.Fatalf("issued_token_type = %v", body["issued_token_type"])
	}
	idjag, _ := body["access_token"].(string)
	claims, err := p.VerifyToken(idjag)
	if err != nil {
		t.Fatalf("verify id-jag: %v", err)
	}
	if claims["aud"] != "ledger" {
		t.Fatalf("aud = %v, want ledger", claims["aud"])
	}
	if claims["sub"] != a.ID {
		t.Fatalf("sub = %v, want %v", claims["sub"], a.ID)
	}
	if claims["client_id"] != a.ID {
		t.Fatalf("client_id = %v, want %v", claims["client_id"], a.ID)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Fatal("id-jag must carry a jti")
	}
	act, _ := claims["act"].(map[string]any)
	if act == nil || act["sub"] != h.ID {
		t.Fatalf("act.sub must be the responsible human %v, got %+v", h.ID, claims["act"])
	}
}

func TestAgentIdentity_WrongAssertion_Rejected(t *testing.T) {
	p, svc, srv, _ := testStackWithIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	wrongPriv, _, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "imposter")
	assertion := signAssertion(t, a.ID, p.IdentityURL(), wrongPriv, time.Now().Add(2*time.Minute))
	resp, _ := postIdentity(t, srv.URL+"/agent/identity", assertion, "ledger")
	if resp.StatusCode == 200 {
		t.Fatal("assertion signed by the wrong key must be rejected")
	}
}

func TestAgentIdentity_MissingAudience_Rejected(t *testing.T) {
	p, svc, srv, _ := testStackWithIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	assertion := signAssertion(t, a.ID, p.IdentityURL(), priv, time.Now().Add(2*time.Minute))
	resp, _ := postIdentity(t, srv.URL+"/agent/identity", assertion, "")
	if resp.StatusCode != 400 {
		t.Fatalf("missing audience must be a 400, got %d", resp.StatusCode)
	}
}

// --- Task 6: agent_auth discovery block ------------------------------------

func TestProvider_Discovery_AgentAuthBlock(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	// auth.md discovers via /.well-known/oauth-authorization-server (RFC 8414).
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("oauth-authorization-server: %v status=%d", err, resp.StatusCode)
	}
	defer resp.Body.Close()
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	aa, ok := d["agent_auth"].(map[string]any)
	if !ok {
		t.Fatalf("discovery missing agent_auth block: %+v", d)
	}
	if aa["identity_endpoint"] != "https://herald.test/agent/identity" {
		t.Fatalf("identity_endpoint = %v", aa["identity_endpoint"])
	}
	types, _ := aa["identity_types_supported"].([]any)
	if len(types) == 0 || types[0] != "identity_assertion" {
		t.Fatalf("identity_types_supported = %v", aa["identity_types_supported"])
	}
	ia, _ := aa["identity_assertion"].(map[string]any)
	at, _ := ia["assertion_types_supported"].([]any)
	if len(at) == 0 || at[0] != "urn:ietf:params:oauth:token-type:id-jag" {
		t.Fatalf("assertion_types_supported = %v", ia["assertion_types_supported"])
	}
}

// --- Task 9: conformance shape ---------------------------------------------

func TestProvider_AgentAuth_ConformanceShape(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var d map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&d)

	// Required top-level fields for an auth.md authorization server.
	for _, k := range []string{"issuer", "token_endpoint", "jwks_uri", "agent_auth"} {
		if _, ok := d[k]; !ok {
			t.Fatalf("conformance: missing %q in discovery", k)
		}
	}
	// jwt-bearer grant must be advertised (the exchange grant).
	grants := toStringSlice(d["grant_types_supported"])
	hasJWTBearer := false
	for _, g := range grants {
		if g == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			hasJWTBearer = true
		}
	}
	if !hasJWTBearer {
		t.Fatalf("conformance: grant_types_supported must include jwt-bearer, got %v", grants)
	}
	aa := d["agent_auth"].(map[string]any)
	ia := aa["identity_assertion"].(map[string]any)
	at := toStringSlice(ia["assertion_types_supported"])
	if len(at) != 1 || at[0] != "urn:ietf:params:oauth:token-type:id-jag" {
		t.Fatalf("conformance: assertion_types_supported must be [id-jag], got %v", at)
	}
}
