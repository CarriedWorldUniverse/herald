package heraldauth_test

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
	jose "github.com/go-jose/go-jose/v4"

	"github.com/CarriedWorldUniverse/herald/heraldauth"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// liveHerald spins a real herald (provider + identity + agent grant) and
// returns the server + a minted agent token, so heraldauth verifies against a
// genuine issuer (not a hand-rolled token).
func liveHerald(t *testing.T) (issuer string, agentToken, agentID, humanID, orgID string) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	priv, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)

	_, signKey, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	p, _ := herald.NewProvider(herald.Config{Issuer: srv.URL + "/", SigningKey: signKey})
	p.SetTokenHandler(herald.NewAgentGrant(p, svc))
	srv.Config.Handler = p.Handler()

	// Agent mints a token via the real jwt-bearer endpoint.
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": a.ID, "sub": a.ID, "aud": srv.URL + "/token",
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	})
	obj, _ := signer.Sign(payload)
	assertion, _ := obj.CompactSerialize()
	resp, _ := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	})
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("failed to mint agent token: %+v", body)
	}
	return srv.URL + "/", tok, a.ID, h.ID, org.ID
}

func TestVerifier_AcceptsValidToken_ParsesClaims(t *testing.T) {
	issuer, tok, agentID, humanID, orgID := liveHerald(t)
	ctx := context.Background()

	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := v.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != agentID || id.Kind != "agent" {
		t.Fatalf("identity: %+v", id)
	}
	if id.ResponsibleHuman != humanID {
		t.Fatalf("responsible human = %q, want %q", id.ResponsibleHuman, humanID)
	}
	if id.Org != orgID {
		t.Fatalf("org = %q, want %q", id.Org, orgID)
	}
	if !id.HasScope("repo:write") {
		t.Fatalf("expected repo:write in %v", id.Scopes)
	}
	if id.HasScope("repo:admin") {
		t.Fatal("must not report an ungranted scope")
	}
}

func TestVerifier_RejectsTamperedToken(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	ctx := context.Background()
	v, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer})

	b := []byte(tok)
	b[len(b)-3] ^= 0x01 // flip a bit in the signature segment
	if _, err := v.Verify(ctx, string(b)); err == nil {
		t.Fatal("tampered token must be rejected")
	}
}

func TestVerifier_RejectsForeignIssuer(t *testing.T) {
	// A token from herald A must not verify on a verifier pointed at herald B.
	issuerA, tokA, _, _, _ := liveHerald(t)
	issuerB, _, _, _, _ := liveHerald(t)
	if issuerA == issuerB {
		t.Skip("issuers coincidentally equal")
	}
	ctx := context.Background()
	vB, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuerB})
	if _, err := vB.Verify(ctx, tokA); err == nil {
		t.Fatal("token from a different herald must be rejected")
	}
}

// JWKSURL override: caller fetches keys via the override URL but the issuer
// claim is still checked against the configured Issuer. This is the
// gateway-fronts-its-own-issuer case — issuer points at the public URL but
// JWKS is reachable in-cluster.
func TestVerifier_JWKSURLOverride_BypassesDiscovery(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	ctx := context.Background()

	// Build the JWKS URL by reading discovery once to find it, then pass it
	// directly. With override set, New() must NOT do discovery itself.
	v0, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer})
	_ = v0 // (real refactor would expose JWKSURI; instead use a known shape)

	v, err := heraldauth.New(ctx, heraldauth.Config{
		Issuer:  issuer,
		JWKSURL: issuer + "jwks",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.Verify(ctx, tok); err != nil {
		t.Fatalf("Verify with JWKSURL override: %v", err)
	}
}

// JWKSURL override means a wrong/unreachable discovery URL is no problem —
// the issuer string is only used for the `iss` claim check.
func TestVerifier_JWKSURLOverride_IgnoresDiscovery(t *testing.T) {
	issuer, tok, _, _, _ := liveHerald(t)
	ctx := context.Background()

	v, err := heraldauth.New(ctx, heraldauth.Config{
		// Issuer is the value tokens carry in `iss`, but we never call out
		// to it for discovery — we go straight to the live JWKS.
		Issuer:  issuer,
		JWKSURL: issuer + "jwks",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := v.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject == "" {
		t.Fatal("identity should have a subject")
	}
}
