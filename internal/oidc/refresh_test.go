package oidc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newRefreshStack(t *testing.T) (*RefreshIssuer, *store.SQLite, store.User) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	org, _ := st.CreateOrg(context.Background(), "acme")
	u, _ := st.CreateUser(context.Background(), store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, err := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return NewRefreshIssuer(p, st, 0), st, u
}

func TestRefreshIssuer_IssueValidateRotate(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)

	tok1, err := ri.Issue(ctx, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rt, err := ri.validate(ctx, tok1)
	if err != nil {
		t.Fatalf("validate fresh: %v", err)
	}
	if rt.UserID != u.ID {
		t.Fatalf("user = %q, want %q", rt.UserID, u.ID)
	}

	tok2, err := ri.rotate(ctx, rt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := ri.validate(ctx, tok2); err != nil {
		t.Fatalf("validate rotated successor: %v", err)
	}
	// The OLD token is now revoked, and reusing it must revoke the chain so the
	// successor also dies (replay defense).
	if _, err := ri.validate(ctx, tok1); err == nil {
		t.Fatal("reused (rotated-away) token must be rejected")
	}
	if _, err := ri.validate(ctx, tok2); err == nil {
		t.Fatal("replay of the old token must revoke the whole chain (successor dead)")
	}
}

func TestRefreshIssuer_RevokeAndGarbage(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)
	tok, _ := ri.Issue(ctx, u.ID)
	ri.revoke(ctx, tok)
	if _, err := ri.validate(ctx, tok); err == nil {
		t.Fatal("revoked token must be rejected")
	}
	ri.revoke(ctx, "garbage-no-dot") // must not panic
	if _, err := ri.validate(ctx, "garbage-no-dot"); err == nil {
		t.Fatal("malformed token must be rejected")
	}
}

func TestRefreshGrant_EndToEnd(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := identity.New(st)
	org, _ := st.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "alice")
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, _ := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	refresh := NewRefreshIssuer(p, st, 0)
	p.SetTokenHandler(NewGrantMux(
		NewAgentGrant(p, svc, refresh),
		NewHumanGrant(p, svc, refresh),
		NewRefreshGrant(p, svc, refresh),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	post := func(form url.Values) map[string]any {
		t.Helper()
		resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("POST /token: %v", err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	// 1. password login -> access + refresh.
	login := post(url.Values{"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"}})
	rtok, _ := login["refresh_token"].(string)
	if rtok == "" {
		t.Fatalf("login returned no refresh_token: %+v", login)
	}

	// 2. refresh -> new access + new refresh.
	r1 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if r1["access_token"] == nil || r1["refresh_token"] == nil {
		t.Fatalf("refresh failed: %+v", r1)
	}
	newR, _ := r1["refresh_token"].(string)

	// 3. the OLD refresh token is now rotated away -> rejected.
	r2 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if r2["error"] == nil {
		t.Fatalf("reused old refresh token should be rejected: %+v", r2)
	}
	// 4. replay revoked the chain -> the once-valid successor is dead too.
	r3 := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {newR}})
	if r3["error"] == nil {
		t.Fatalf("successor after replay should be rejected: %+v", r3)
	}
}

func TestRevokeEndpoint(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	svc := identity.New(st)
	org, _ := st.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "alice")
	_ = svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2")

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, _ := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	refresh := NewRefreshIssuer(p, st, 0)
	p.SetTokenHandler(NewGrantMux(NewAgentGrant(p, svc, refresh), NewHumanGrant(p, svc, refresh), NewRefreshGrant(p, svc, refresh)))
	p.SetRevokeHandler(NewRevokeHandler(refresh))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	post := func(path string, form url.Values) (int, map[string]any) {
		resp, err := http.Post(srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	_, login := post("/token", url.Values{"grant_type": {"password"}, "username": {h.ID}, "password": {"hunter2hunter2"}})
	rtok, _ := login["refresh_token"].(string)

	code, _ := post("/revoke", url.Values{"token": {rtok}})
	if code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", code)
	}
	// Revoked -> refresh now fails.
	_, after := post("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rtok}})
	if after["error"] == nil {
		t.Fatalf("refresh after revoke should fail: %+v", after)
	}
	// Idempotent + no enumeration: revoking garbage is still 200.
	if code, _ := post("/revoke", url.Values{"token": {"garbage"}}); code != http.StatusOK {
		t.Fatalf("revoke garbage status = %d, want 200", code)
	}
}
