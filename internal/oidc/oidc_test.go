package oidc_test

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
)

func newTestProvider(t *testing.T) *herald.Provider {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	p, err := herald.NewProvider(herald.Config{Issuer: "https://herald.test/", SigningKey: priv})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func TestProvider_JWKSHasEdDSAKey(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/jwks")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("jwks: %v status=%d", err, resp.StatusCode)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("jwks has no keys")
	}
	k := jwks.Keys[0]
	if k["kty"] != "OKP" || k["crv"] != "Ed25519" {
		t.Fatalf("expected OKP/Ed25519 key, got %+v", k)
	}
	if k["use"] != "sig" || k["kid"] == "" || k["kid"] == nil {
		t.Fatalf("key missing use=sig / kid: %+v", k)
	}
	// JWKS must never leak the private key component "d".
	if _, leaked := k["d"]; leaked {
		t.Fatal("JWKS leaked private key component 'd'")
	}
}

func TestProvider_Discovery(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("discovery: %v status=%d", err, resp.StatusCode)
	}
	defer resp.Body.Close()
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if d["issuer"] != "https://herald.test/" {
		t.Fatalf("issuer = %v", d["issuer"])
	}
	if d["jwks_uri"] == "" || d["token_endpoint"] == "" {
		t.Fatalf("discovery missing jwks_uri/token_endpoint: %+v", d)
	}
	algs, _ := d["id_token_signing_alg_values_supported"].([]any)
	found := false
	for _, a := range algs {
		if a == "EdDSA" {
			found = true
		}
	}
	if !found {
		t.Fatalf("EdDSA not advertised: %+v", d["id_token_signing_alg_values_supported"])
	}

	// Authorization-code flow (A5): the discovery doc must advertise the
	// /authorize endpoint, PKCE S256, the code response type (there is no
	// implicit flow — "token" was never backed by a handler), and the
	// authorization_code grant.
	if d["authorization_endpoint"] != "https://herald.test/authorize" {
		t.Fatalf("authorization_endpoint = %v", d["authorization_endpoint"])
	}
	if got := anyStrings(d["code_challenge_methods_supported"]); len(got) != 1 || got[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported = %v", d["code_challenge_methods_supported"])
	}
	if got := anyStrings(d["response_types_supported"]); len(got) != 1 || got[0] != "code" {
		t.Fatalf("response_types_supported = %v (want exactly [code])", d["response_types_supported"])
	}
	grants := anyStrings(d["grant_types_supported"])
	if !containsString(grants, "authorization_code") {
		t.Fatalf("authorization_code not in grant_types_supported: %v", grants)
	}
	if !containsString(grants, "urn:ietf:params:oauth:grant-type:jwt-bearer") {
		t.Fatalf("jwt-bearer dropped from grant_types_supported: %v", grants)
	}
}

// anyStrings converts a decoded-JSON []any into []string.
func anyStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, a := range arr {
		if s, ok := a.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func TestProvider_AuthorizeRouting(t *testing.T) {
	p := newTestProvider(t)
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	// Unconfigured: 501.
	resp, err := http.Get(srv.URL + "/authorize")
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("unconfigured /authorize status = %d, want 501", resp.StatusCode)
	}

	// Configured: both GET and POST reach the handler.
	var gotMethods []string
	p.SetAuthorizeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethods = append(gotMethods, r.Method)
		w.WriteHeader(http.StatusTeapot)
	}))
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req, _ := http.NewRequest(method, srv.URL+"/authorize", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s /authorize: %v", method, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusTeapot {
			t.Fatalf("%s /authorize status = %d, want stub's 418", method, resp.StatusCode)
		}
	}
	if len(gotMethods) != 2 || gotMethods[0] != "GET" || gotMethods[1] != "POST" {
		t.Fatalf("stub saw methods %v, want [GET POST]", gotMethods)
	}
}

func TestProvider_SignAndVerifyRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	// Sign a token with arbitrary claims, then verify it with the provider's
	// public verifier (the same path heraldauth will use).
	tok, err := p.SignToken(map[string]any{
		"sub":   "agent-123",
		"org":   "org-abc",
		"scope": "repo:read repo:write",
	})
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["sub"] != "agent-123" || claims["org"] != "org-abc" {
		t.Fatalf("claims roundtrip mismatch: %+v", claims)
	}
	// iss/iat/exp must be stamped by SignToken.
	if claims["iss"] != "https://herald.test/" {
		t.Fatalf("iss not stamped: %v", claims["iss"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatal("exp not stamped")
	}
}

func TestProvider_VerifyRejectsTampered(t *testing.T) {
	p := newTestProvider(t)
	tok, _ := p.SignToken(map[string]any{"sub": "x"})
	// Flip a character in the payload segment.
	b := []byte(tok)
	for i := len(b) / 2; i < len(b); i++ {
		if b[i] != '.' {
			if b[i] == 'A' {
				b[i] = 'B'
			} else {
				b[i] = 'A'
			}
			break
		}
	}
	if _, err := p.VerifyToken(string(b)); err == nil {
		t.Fatal("expected verify to reject a tampered token")
	}
}
