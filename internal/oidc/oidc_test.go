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
