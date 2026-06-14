package heraldauth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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

// liveHeraldIDJAG spins a real herald, registers an agent, and mints an ID-JAG
// scoped to `audience` via the real /agent/identity endpoint.
func liveHeraldIDJAG(t *testing.T, audience string) (issuer, idjag, agentID, humanID string) {
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
	slug := fmt.Sprintf("anvil-%d", liveHeraldSeq.Add(1))
	priv, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), slug)
	a, err := svc.CreateAgent(ctx, org.ID, slug, h.ID, pub)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)

	_, signKey, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(nil)
	t.Cleanup(srv.Close)
	p, _ := herald.NewProvider(herald.Config{Issuer: srv.URL + "/", SigningKey: signKey})
	ag := herald.NewAgentGrant(p, svc, nil)
	p.SetTokenHandler(ag)
	p.SetIdentityHandler(http.HandlerFunc(ag.ServeIdentity))
	srv.Config.Handler = p.Handler()

	// Agent self-signs a proof-of-possession assertion (aud = identity endpoint).
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"))
	payload, _ := json.Marshal(map[string]any{
		"iss": a.ID, "sub": a.ID, "aud": p.IdentityURL(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	})
	obj, _ := signer.Sign(payload)
	assertion, _ := obj.CompactSerialize()

	resp, _ := http.PostForm(srv.URL+"/agent/identity", url.Values{
		"type":      {"identity_assertion"},
		"assertion": {assertion},
		"audience":  {audience},
	})
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("failed to mint id-jag: %+v", body)
	}
	return srv.URL + "/", tok, a.ID, h.ID
}

func TestIDJAG_E2E_MatchingAudience_Accepted(t *testing.T) {
	ctx := context.Background()
	issuer, idjag, agentID, humanID := liveHeraldIDJAG(t, "ledger")
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer, Audience: "ledger"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := v.Verify(ctx, idjag)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id.Subject != agentID {
		t.Fatalf("subject = %q, want %q", id.Subject, agentID)
	}
	if id.ResponsibleHuman != humanID {
		t.Fatalf("responsible human = %q, want %q", id.ResponsibleHuman, humanID)
	}
}

func TestIDJAG_E2E_WrongAudience_Rejected(t *testing.T) {
	ctx := context.Background()
	issuer, idjag, _, _ := liveHeraldIDJAG(t, "ledger")
	v, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer, Audience: "cairn"})
	if _, err := v.Verify(ctx, idjag); err == nil {
		t.Fatal("an ID-JAG scoped to ledger must be rejected by a cairn verifier")
	}
}

func TestIDJAG_E2E_Replay_Rejected(t *testing.T) {
	ctx := context.Background()
	issuer, idjag, _, _ := liveHeraldIDJAG(t, "ledger")
	v, _ := heraldauth.New(ctx, heraldauth.Config{Issuer: issuer, Audience: "ledger"})
	if _, err := v.Verify(ctx, idjag); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := v.Verify(ctx, idjag); err == nil {
		t.Fatal("re-presenting the same ID-JAG (same jti) must be rejected as replay")
	}
}
