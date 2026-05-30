package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	casket "github.com/CarriedWorldUniverse/casket-go"
	jose "github.com/go-jose/go-jose/v4"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

const grantTestSeed = "owner-seed-32-bytes-padded-xxxxx"

// testStack builds a provider + identity service sharing an in-memory store,
// with the agent grant wired into the token endpoint.
func testStack(t *testing.T) (*herald.Provider, *identity.Service, *httptest.Server) {
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
	p.SetTokenHandler(herald.NewAgentGrant(p, svc))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, svc, srv
}

// signAssertion builds a casket-signed jwt-bearer assertion: iss=sub=agentID,
// aud=token endpoint, short exp, EdDSA with the agent's casket private key.
func signAssertion(t *testing.T, agentID, aud string, priv ed25519.PrivateKey, exp time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	payload, _ := json.Marshal(map[string]any{
		"iss": agentID, "sub": agentID, "aud": aud,
		"iat": time.Now().Unix(), "exp": exp.Unix(),
	})
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

func postAssertion(t *testing.T, tokenURL, assertion string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	return resp, body
}

func TestAgentGrant_CasketSignedAssertion_IssuesToken(t *testing.T) {
	p, svc, srv := testStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)
	_ = svc.GrantScope(ctx, a.ID, "repo:read", h.ID)

	assertion := signAssertion(t, a.ID, srv.URL+"/token", priv, time.Now().Add(2*time.Minute))
	resp, body := postAssertion(t, srv.URL+"/token", assertion)
	if resp.StatusCode != 200 {
		t.Fatalf("token endpoint status=%d body=%+v", resp.StatusCode, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token in %+v", body)
	}

	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("verify issued token: %v", err)
	}
	if claims["sub"] != a.ID {
		t.Fatalf("sub = %v, want %v", claims["sub"], a.ID)
	}
	act, _ := claims["act"].(map[string]any)
	if act == nil || act["sub"] != h.ID {
		t.Fatalf("act.sub must be the responsible human %v, got %+v", h.ID, claims["act"])
	}
	if claims["org"] != org.ID {
		t.Fatalf("org = %v", claims["org"])
	}
	if claims["kind"] != "agent" {
		t.Fatalf("kind = %v", claims["kind"])
	}
	sc, _ := claims["scope"].(string)
	if !strings.Contains(sc, "repo:write") || !strings.Contains(sc, "repo:read") {
		t.Fatalf("scope = %q", sc)
	}
	if claims["agent_fp"] != a.CasketFingerprint {
		t.Fatalf("agent_fp = %v, want %v", claims["agent_fp"], a.CasketFingerprint)
	}
}

func TestAgentGrant_WrongKey_Rejected(t *testing.T) {
	_, svc, srv := testStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	// Sign with a DIFFERENT key than the one registered for the agent.
	wrongPriv, _, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "imposter")
	assertion := signAssertion(t, a.ID, srv.URL+"/token", wrongPriv, time.Now().Add(2*time.Minute))
	resp, _ := postAssertion(t, srv.URL+"/token", assertion)
	if resp.StatusCode == 200 {
		t.Fatal("assertion signed by the wrong key must be rejected")
	}
}

func TestAgentGrant_BlockedHuman_Rejected(t *testing.T) {
	_, svc, srv := testStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	_ = svc.BlockUser(ctx, h.ID) // cascade: agent must not be able to mint

	assertion := signAssertion(t, a.ID, srv.URL+"/token", priv, time.Now().Add(2*time.Minute))
	resp, _ := postAssertion(t, srv.URL+"/token", assertion)
	if resp.StatusCode == 200 {
		t.Fatal("agent of a blocked human must be rejected (cascade)")
	}
}

func TestAgentGrant_ExpiredAssertion_Rejected(t *testing.T) {
	_, svc, srv := testStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	assertion := signAssertion(t, a.ID, srv.URL+"/token", priv, time.Now().Add(-1*time.Minute))
	resp, _ := postAssertion(t, srv.URL+"/token", assertion)
	if resp.StatusCode == 200 {
		t.Fatal("expired assertion must be rejected")
	}
}

func TestAgentGrant_ClientCannotForgeResponsibleHuman(t *testing.T) {
	// Even if a client crafts an assertion with extra claims, herald stamps
	// act.sub from the AGENT RECORD, never from client input. We assert the
	// issued token's act.sub equals the registered responsible human.
	p, svc, srv := testStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	realHuman, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte(grantTestSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", realHuman.ID, pub)

	// Craft an assertion that *also* claims a different "act"/"responsible_human".
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": a.ID, "sub": a.ID, "aud": srv.URL + "/token",
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
		"act":               map[string]any{"sub": "human:imposter"},
		"responsible_human": "human:imposter",
	})
	obj, _ := signer.Sign(payload)
	assertion, _ := obj.CompactSerialize()

	resp, body := postAssertion(t, srv.URL+"/token", assertion)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d body=%+v", resp.StatusCode, body)
	}
	claims, _ := p.VerifyToken(body["access_token"].(string))
	act, _ := claims["act"].(map[string]any)
	if act["sub"] != realHuman.ID {
		t.Fatalf("herald must stamp act.sub from the record (%v), not client input; got %v", realHuman.ID, act["sub"])
	}
}
