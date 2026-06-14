package heraldauth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CarriedWorldUniverse/herald/heraldauth"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
)

func TestVerifier_AudienceOptIn_BackwardCompatible(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	ctx := context.Background()
	// No Audience configured → aud is not enforced (existing behavior).
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("a verifier with no Audience must still accept a general token: %v", err)
	}
}

func TestVerifier_AudienceConfigured_RejectsTokenWithoutMatchingAud(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	ctx := context.Background()
	// Audience configured, but the general token carries no `aud` → reject.
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer, Audience: "ledger"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(ctx, tok); err == nil {
		t.Fatal("a verifier configured with Audience must reject a token lacking that aud")
	}
}

// liveHeraldWithClaims spins a real herald and returns a token herald itself
// signed over the given extra claims (merged with iss/iat/exp), so heraldauth
// verifies a genuine-issuer token whose shape we control (e.g. carrying jti).
func liveHeraldWithClaims(t *testing.T, extra map[string]any) (issuer, token string) {
	t.Helper()
	_, signKey, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	p, _ := herald.NewProvider(herald.Config{Issuer: srv.URL + "/", SigningKey: signKey})
	srv.Config.Handler = p.Handler()
	tok, err := p.SignToken(extra)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	return srv.URL + "/", tok
}

func TestVerifier_ReplayedJTI_Rejected(t *testing.T) {
	ctx := context.Background()
	issuer, tok := liveHeraldWithClaims(t, map[string]any{
		"sub": "agent:anvil", "kind": "agent", "jti": "jti-replay-001",
	})
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("first presentation must succeed: %v", err)
	}
	if _, err := v.Verify(ctx, tok); err == nil {
		t.Fatal("second presentation of the same jti must be rejected as a replay")
	}
}

func TestVerifier_DistinctJTI_BothAccepted(t *testing.T) {
	ctx := context.Background()
	issuer1, tok1 := liveHeraldWithClaims(t, map[string]any{"sub": "a", "jti": "jti-A"})
	v1, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer1})
	if _, err := v1.Verify(ctx, tok1); err != nil {
		t.Fatalf("tok1: %v", err)
	}
	issuer2, tok2 := liveHeraldWithClaims(t, map[string]any{"sub": "a", "jti": "jti-B"})
	v2, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer2})
	if _, err := v2.Verify(ctx, tok2); err != nil {
		t.Fatalf("distinct jti must be accepted: %v", err)
	}
}

func TestProtectedResourceHandler_PointsAtHerald(t *testing.T) {
	h := heraldauth.ProtectedResourceHandler("ledger", "https://herald.test/")
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/.well-known/oauth-protected-resource")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("get: %v status=%d", err, resp.StatusCode)
	}
	defer resp.Body.Close()
	var d map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d["resource"] != "ledger" {
		t.Fatalf("resource = %v, want ledger", d["resource"])
	}
	servers, _ := d["authorization_servers"].([]any)
	if len(servers) != 1 || servers[0] != "https://herald.test/" {
		t.Fatalf("authorization_servers = %v, want [https://herald.test/]", d["authorization_servers"])
	}
}
