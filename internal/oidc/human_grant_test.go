package oidc_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func humanStack(t *testing.T) (*identity.Service, *httptest.Server, string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)

	org, err := s.CreateOrg(context.Background(), "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	_, priv, _ := ed25519.GenerateKey(nil)
	p, err := herald.NewProvider(herald.Config{Issuer: "https://herald.test/", SigningKey: priv})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	p.SetTokenHandler(herald.NewGrantMux(herald.NewAgentGrant(p, svc, nil), herald.NewHumanGrant(p, svc, nil), herald.NewRefreshGrant(p, svc, nil), nil))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return svc, srv, org.ID
}

func TestHumanGrant_PasswordLogin(t *testing.T) {
	ctx := context.Background()
	svc, srv, orgID := humanStack(t)

	h, err := svc.CreateHuman(ctx, orgID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.GrantScope(ctx, h.ID, "issue:write", h.ID); err != nil {
		t.Fatalf("GrantScope: %v", err)
	}
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	tok := postToken(t, srv.URL, url.Values{
		"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"},
	}, http.StatusOK)
	claims := decodeJWT(t, tok)
	if claims["kind"] != "human" || claims["sub"] != h.ID || claims["org"] != orgID {
		t.Fatalf("claims = %v", claims)
	}
	if sc, _ := claims["scope"].(string); !strings.Contains(sc, "issue:write") {
		t.Fatalf("scope = %v, want issue:write", claims["scope"])
	}

	postToken(t, srv.URL, url.Values{
		"grant_type": {"password"}, "username": {h.ID}, "password": {"nope"},
	}, http.StatusUnauthorized)

	postToken(t, srv.URL, url.Values{"grant_type": {"client_credentials"}}, http.StatusBadRequest)
}

func postToken(t *testing.T, base string, form url.Values, wantStatus int) string {
	t.Helper()
	resp, err := http.PostForm(base+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("POST /token status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return out.AccessToken
}

func TestHumanGrant_ProductsClaim(t *testing.T) {
	ctx := context.Background()
	svc, srv, orgID := humanStack(t)

	h, err := svc.CreateHuman(ctx, orgID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	// Disable ledger so the products claim should be [cairn, commonplace].
	if err := svc.DisableProduct(ctx, orgID, identity.ProductLedger); err != nil {
		t.Fatalf("DisableProduct: %v", err)
	}

	tok := postToken(t, srv.URL, url.Values{
		"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"},
	}, http.StatusOK)
	claims := decodeJWT(t, tok)
	if got := joinStrs(toStringSlice(claims["products"])); got != "cairn,commonplace" {
		t.Fatalf("products = %q, want \"cairn,commonplace\"", got)
	}
}

func decodeJWT(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return m
}
