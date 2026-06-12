package oidc_test

import (
	"context"
	"crypto/sha256"
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

// codeStack wires a provider whose GrantMux includes the authorization_code
// grant (same fixture pattern as humanStack, plus a CodeStore + refresh).
func codeStack(t *testing.T) (*identity.Service, *herald.Provider, *herald.CodeStore, *httptest.Server, string) {
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

	p := newTestProvider(t)
	codes := herald.NewCodeStore(nil)
	refresh := herald.NewRefreshIssuer(p, s, 0)
	p.SetTokenHandler(herald.NewGrantMux(
		herald.NewAgentGrant(p, svc, nil),
		herald.NewHumanGrant(p, svc, nil),
		herald.NewRefreshGrant(p, svc, nil),
		herald.NewCodeGrant(p, svc, codes, refresh),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return svc, p, codes, srv, org.ID
}

// s256 derives the PKCE S256 code_challenge for a verifier (RFC 7636).
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// postTokenRaw POSTs the form and returns status + decoded JSON body.
func postTokenRaw(t *testing.T, base string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(base+"/token", form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return resp.StatusCode, out
}

func TestCodeGrant_HappyPath(t *testing.T) {
	ctx := context.Background()
	svc, p, codes, srv, orgID := codeStack(t)

	h, err := svc.CreateHuman(ctx, orgID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.GrantScope(ctx, h.ID, "issue:write", h.ID); err != nil {
		t.Fatalf("GrantScope: %v", err)
	}

	const verifier = "correct-horse-battery-staple-correct-horse"
	code := codes.Issue(herald.PendingAuth{
		ClientID:      "panel",
		RedirectURI:   "https://panel.test/cb",
		UserID:        h.ID,
		CodeChallenge: s256(verifier),
	})

	status, body := postTokenRaw(t, srv.URL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://panel.test/cb"},
		"client_id":     {"panel"},
		"code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, body = %+v", status, body)
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type = %v, want Bearer", body["token_type"])
	}
	if _, ok := body["expires_in"].(float64); !ok {
		t.Fatalf("expires_in missing/not numeric: %+v", body)
	}
	if rt, _ := body["refresh_token"].(string); rt == "" {
		t.Fatalf("refresh_token missing: %+v", body)
	}

	// The access token must verify as a herald human token for alice.
	tok, _ := body["access_token"].(string)
	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["kind"] != "human" || claims["sub"] != h.ID || claims["org"] != orgID {
		t.Fatalf("claims = %v", claims)
	}
	if sc, _ := claims["scope"].(string); !strings.Contains(sc, "issue:write") {
		t.Fatalf("scope = %v, want issue:write", claims["scope"])
	}
}

func TestCodeGrant_Rejections(t *testing.T) {
	ctx := context.Background()
	svc, _, codes, srv, orgID := codeStack(t)

	h, err := svc.CreateHuman(ctx, orgID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}

	const verifier = "correct-horse-battery-staple-correct-horse"
	issue := func() string {
		return codes.Issue(herald.PendingAuth{
			ClientID:      "panel",
			RedirectURI:   "https://panel.test/cb",
			UserID:        h.ID,
			CodeChallenge: s256(verifier),
		})
	}
	form := func(code, clientID, redirect, ver string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {redirect},
			"client_id":     {clientID},
			"code_verifier": {ver},
		}
	}
	expectRejected := func(name string, f url.Values) {
		t.Helper()
		status, body := postTokenRaw(t, srv.URL, f)
		if status != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401 (body %+v)", name, status, body)
		}
		// Uniform error so probing reveals nothing about which check failed.
		if body["error"] != "invalid_grant" || body["error_description"] != "code rejected" {
			t.Fatalf("%s: body = %+v, want invalid_grant / code rejected", name, body)
		}
	}

	expectRejected("unknown code", form("no-such-code", "panel", "https://panel.test/cb", verifier))
	expectRejected("wrong verifier", form(issue(), "panel", "https://panel.test/cb", "wrong-verifier-wrong-verifier-wrong"))
	expectRejected("wrong client_id", form(issue(), "evil", "https://panel.test/cb", verifier))
	expectRejected("wrong redirect_uri", form(issue(), "panel", "https://evil.test/cb", verifier))

	// Replay: first exchange succeeds, second is rejected.
	code := issue()
	good := form(code, "panel", "https://panel.test/cb", verifier)
	if status, body := postTokenRaw(t, srv.URL, good); status != http.StatusOK {
		t.Fatalf("first exchange: status = %d, body = %+v", status, body)
	}
	expectRejected("replayed code", good)

	// A failed exchange consumes the code: the correct request afterwards fails.
	code = issue()
	expectRejected("bad client burns code", form(code, "evil", "https://panel.test/cb", verifier))
	expectRejected("burned code", form(code, "panel", "https://panel.test/cb", verifier))

	// Blocked user: code issued, user blocked before exchange -> rejected.
	code = issue()
	if err := svc.BlockUser(ctx, h.ID); err != nil {
		t.Fatalf("BlockUser: %v", err)
	}
	expectRejected("blocked user", form(code, "panel", "https://panel.test/cb", verifier))
}

func TestGrantMux_AuthorizationCodeDispatch(t *testing.T) {
	// Mux without a code grant wired: authorization_code -> unsupported.
	svc := identity.New(mustOpenStore(t))
	p := newTestProvider(t)
	p.SetTokenHandler(herald.NewGrantMux(
		herald.NewAgentGrant(p, svc, nil),
		herald.NewHumanGrant(p, svc, nil),
		herald.NewRefreshGrant(p, svc, nil),
		nil,
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	status, body := postTokenRaw(t, srv.URL, url.Values{"grant_type": {"authorization_code"}})
	if status != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Fatalf("status = %d, body = %+v, want 400 unsupported_grant_type", status, body)
	}
}

func mustOpenStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
