package oidc_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// TestAuthorizationCodeFlowEndToEnd walks the full authorization-code dance
// over httptest exactly as a browser + RP would, through the real
// Provider.Handler() mux: GET /authorize (login form) -> POST /authorize
// (credentials, 302 with code) -> POST /token (PKCE exchange) -> verified
// herald access token. The point is proving the A1-A5 pieces COMPOSE.
func TestAuthorizationCodeFlowEndToEnd(t *testing.T) {
	ctx := context.Background()

	// Full stack: in-memory store, identity service, org, registered client,
	// code store, provider with BOTH /authorize and the grant mux wired.
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)

	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	clients, err := herald.ParseClients("atlas|https://a/cb")
	if err != nil {
		t.Fatalf("ParseClients: %v", err)
	}
	p := newTestProvider(t)
	codes := herald.NewCodeStore(nil)
	refresh := herald.NewRefreshIssuer(p, s, 0)
	p.SetAuthorizeHandler(herald.NewAuthorize(clients, codes, svc))
	p.SetTokenHandler(herald.NewGrantMux(
		herald.NewAgentGrant(p, svc, nil),
		herald.NewHumanGrant(p, svc, nil),
		herald.NewRefreshGrant(p, svc, nil),
		herald.NewCodeGrant(p, svc, codes, refresh),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	// A human with a password — the resource owner who will log in.
	h, err := svc.CreateHuman(ctx, org.ID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.SetHumanPassword(ctx, h.ID, "hunter2hunter2"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}

	const verifier = "correct-horse-battery-staple-correct-horse"
	authzParams := url.Values{
		"client_id":             {"atlas"},
		"redirect_uri":          {"https://a/cb"},
		"response_type":         {"code"},
		"state":                 {"st8"},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
	}

	// Step 1: the browser lands on /authorize and gets the hosted login form.
	resp, err := http.Get(srv.URL + "/authorize?" + authzParams.Encode())
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /authorize status = %d, body = %s", resp.StatusCode, page)
	}
	for _, want := range []string{`name="username"`, `name="password"`} {
		if !strings.Contains(string(page), want) {
			t.Fatalf("login form missing %s; body = %s", want, page)
		}
	}
	// Capture the CSRF double-submit pair the browser would hold: the
	// __Host- cookie from Set-Cookie and the hidden csrf_token form field.
	// Replayed manually rather than via a cookiejar: Go's jar (correctly)
	// refuses to send Secure cookies back over the plain-HTTP httptest URL.
	var csrfCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if strings.Contains(c.Name, "herald_authz_csrf") {
			csrfCookie = c
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatalf("GET /authorize did not set CSRF cookie; got %v", resp.Cookies())
	}
	m := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(page)
	if m == nil {
		t.Fatalf("csrf_token hidden field missing from login form: %s", page)
	}

	// Step 2: the user submits credentials (+ the CSRF pair); herald
	// redirects back to the client with a single-use code and the
	// round-tripped state.
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	form := url.Values{"username": {h.ID}, "password": {"hunter2hunter2"}, "csrf_token": {string(m[1])}}
	for k, v := range authzParams {
		form[k] = v
	}
	postReq, err := http.NewRequest("POST", srv.URL+"/authorize", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build POST /authorize: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{Name: csrfCookie.Name, Value: csrfCookie.Value})
	resp, err = noRedirect.Do(postReq)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize status = %d, want 302; body = %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", resp.Header.Get("Location"), err)
	}
	if loc.Scheme != "https" || loc.Host != "a" || loc.Path != "/cb" {
		t.Fatalf("redirected to %q, want https://a/cb", loc.String())
	}
	if loc.Query().Get("state") != "st8" {
		t.Fatalf("state = %q, want st8", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", loc.String())
	}

	// Step 3: the RP exchanges the code (+ PKCE verifier) at /token.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"https://a/cb"},
		"client_id":     {"atlas"},
		"code_verifier": {verifier},
	}
	status, tok := postTokenRaw(t, srv.URL, tokenForm)
	if status != http.StatusOK {
		t.Fatalf("POST /token status = %d, body = %+v", status, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("access_token missing: %+v", tok)
	}
	if rt, _ := tok["refresh_token"].(string); rt == "" {
		t.Fatalf("refresh_token missing (real RefreshIssuer wired): %+v", tok)
	}

	// Step 4: the access token verifies as a herald human token for alice.
	claims, err := p.VerifyToken(access)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["kind"] != "human" || claims["sub"] != h.ID || claims["org"] != org.ID {
		t.Fatalf("claims = %v, want kind=human sub=%s org=%s", claims, h.ID, org.ID)
	}

	// Replaying the consumed code must be rejected.
	status, replay := postTokenRaw(t, srv.URL, tokenForm)
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed code: status = %d, want 401 (body %+v)", status, replay)
	}

	// An unregistered redirect_uri at /authorize must 400, never redirect.
	bad := url.Values{}
	for k, v := range authzParams {
		bad[k] = v
	}
	bad.Set("redirect_uri", "https://evil/cb")
	resp, err = noRedirect.Get(srv.URL + "/authorize?" + bad.Encode())
	if err != nil {
		t.Fatalf("GET /authorize (bad redirect): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered redirect: status = %d, want 400", resp.StatusCode)
	}
	if l := resp.Header.Get("Location"); l != "" {
		t.Fatalf("unregistered redirect must not redirect, got Location %q", l)
	}
}
