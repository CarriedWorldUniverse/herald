package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// stubHumans satisfies HumanResolver for handler tests. The embedded nil
// IdentityResolver is safe: /authorize only calls VerifyHumanPassword.
type stubHumans struct{ IdentityResolver }

func (stubHumans) VerifyHumanPassword(_ context.Context, userID, pw string) (store.User, error) {
	if userID == "u-good" && pw == "pw" {
		return store.User{ID: "u-good", Kind: store.KindHuman}, nil
	}
	return store.User{}, errStubBadLogin
}

var errStubBadLogin = errEnumStub("bad login")

type errEnumStub string

func (e errEnumStub) Error() string { return string(e) }

func newAuthorizeForTest(t *testing.T) *Authorize {
	t.Helper()
	clients, err := ParseClients("atlas|https://a/cb")
	if err != nil {
		t.Fatal(err)
	}
	return NewAuthorize(clients, NewCodeStore(nil), stubHumans{})
}

const authzQuery = "client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&state=xyz&code_challenge=abc123&code_challenge_method=S256"

var csrfFieldRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// getLoginForm simulates the browser GET /authorize: returns the CSRF cookie
// the server set and the matching csrf_token hidden-field value from the
// rendered form (the double-submit pair the POST must echo back).
func getLoginForm(t *testing.T, a *Authorize) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+authzQuery, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /authorize status %d body %s", rec.Code, rec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("GET /authorize did not set the CSRF cookie")
	}
	m := csrfFieldRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("csrf_token hidden field missing from login form")
	}
	if m[1] != cookie.Value {
		t.Fatalf("hidden field %q != cookie %q (double-submit pair must match)", m[1], cookie.Value)
	}
	return cookie, m[1]
}

// postAuthorize sends a login POST, attaching cookie when non-nil.
func postAuthorize(a *Authorize, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func validLoginForm() url.Values {
	return url.Values{
		"client_id": {"atlas"}, "redirect_uri": {"https://a/cb"}, "response_type": {"code"},
		"state": {"xyz"}, "code_challenge": {"abc123"}, "code_challenge_method": {"S256"},
		"username": {"u-good"}, "password": {"pw"},
	}
}

func TestAuthorizeGetRendersForm(t *testing.T) {
	a := newAuthorizeForTest(t)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+authzQuery, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`name="username"`, `name="password"`, `value="xyz"`, `value="abc123"`, `name="csrf_token"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form missing %s", want)
		}
	}
	var csrf *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrf = c
		}
	}
	if csrf == nil {
		t.Fatal("CSRF cookie not set on GET")
	}
	if !csrf.Secure || !csrf.HttpOnly || csrf.Path != "/" || csrf.SameSite != http.SameSiteLaxMode || csrf.MaxAge != 600 {
		t.Errorf("CSRF cookie flags wrong: %+v", csrf)
	}
}

// TestAuthorizeGetReusesExistingCSRFCookie pins GET idempotence: a duplicate
// GET (browser prerender, second tab) that already carries the CSRF cookie
// must NOT overwrite it — otherwise the earlier-rendered form still embeds
// the old token and its submit fails the double-submit check.
func TestAuthorizeGetReusesExistingCSRFCookie(t *testing.T) {
	a := newAuthorizeForTest(t)
	cookie, _ := getLoginForm(t, a)

	req := httptest.NewRequest("GET", "/authorize?"+authzQuery, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second GET status %d body %s", rec.Code, rec.Body.String())
	}
	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("second GET with CSRF cookie must not set a cookie, got %v", sc)
	}
	m := csrfFieldRE.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("csrf_token hidden field missing from login form")
	}
	if m[1] != cookie.Value {
		t.Errorf("form field %q must reuse inbound cookie value %q", m[1], cookie.Value)
	}
}

// TestAuthorizeGetMintsFreshTokenWithoutCookie pins the mint path: cookieless
// GETs each get their own token (no cross-request reuse without a cookie).
func TestAuthorizeGetMintsFreshTokenWithoutCookie(t *testing.T) {
	a := newAuthorizeForTest(t)
	c1, t1 := getLoginForm(t, a)
	c2, t2 := getLoginForm(t, a)
	if t1 == t2 || c1.Value == c2.Value {
		t.Errorf("cookieless GETs must mint distinct tokens, both got %q", t1)
	}
}

func TestAuthorizeGetRejectsBadClientWithoutRedirect(t *testing.T) {
	a := newAuthorizeForTest(t)
	for _, q := range []string{
		"client_id=ghost&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fevil%2Fcb&response_type=code&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=token&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&code_challenge=c&code_challenge_method=plain",
	} {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+q, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: want 400, got %d", q, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("query %q: must not redirect on validation failure, got Location %s", q, loc)
		}
	}
}

func TestAuthorizePostGoodLoginRedirectsWithCode(t *testing.T) {
	a := newAuthorizeForTest(t)
	cookie, token := getLoginForm(t, a)
	form := validLoginForm()
	form.Set("csrf_token", token)
	rec := postAuthorize(a, form, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	// Single-use: the successful login must expire the CSRF cookie.
	expired := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName && c.MaxAge < 0 {
			expired = true
		}
	}
	if !expired {
		t.Error("CSRF cookie not expired on successful login")
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host != "a" {
		t.Fatalf("bad Location %q", rec.Header().Get("Location"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Error("state not round-tripped")
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in redirect")
	}
	pa, ok := a.codes.Redeem(code)
	if !ok || pa.UserID != "u-good" || pa.CodeChallenge != "abc123" {
		t.Fatalf("stored pending auth wrong: %+v ok=%v", pa, ok)
	}
}

func TestAuthorizePostBadLoginRerendersForm(t *testing.T) {
	a := newAuthorizeForTest(t)
	cookie, token := getLoginForm(t, a)
	form := validLoginForm()
	form.Set("password", "WRONG")
	form.Set("csrf_token", token)
	rec := postAuthorize(a, form, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 re-render on bad login, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "login failed") {
		t.Error("error message missing from re-rendered form")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Error("must not redirect on bad login")
	}
	// The re-rendered form must carry a FRESH double-submit pair so the retry
	// can succeed (the spent token was rotated).
	var fresh *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName && c.MaxAge > 0 {
			fresh = c
		}
	}
	if fresh == nil || fresh.Value == "" || fresh.Value == token {
		t.Fatalf("bad login must rotate the CSRF cookie, got %+v", fresh)
	}
	m := csrfFieldRE.FindStringSubmatch(rec.Body.String())
	if m == nil || m[1] != fresh.Value {
		t.Fatalf("re-rendered form field does not match rotated cookie: %v vs %q", m, fresh.Value)
	}
}

func TestAuthorizePostMissingCSRFCookieForbidden(t *testing.T) {
	a := newAuthorizeForTest(t)
	_, token := getLoginForm(t, a)
	form := validLoginForm()
	form.Set("csrf_token", token)
	rec := postAuthorize(a, form, nil) // field present, cookie absent
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF cookie: want 403, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("CSRF failure must not redirect, got Location %s", loc)
	}
}

func TestAuthorizePostCSRFMismatchForbidden(t *testing.T) {
	a := newAuthorizeForTest(t)
	cookie, _ := getLoginForm(t, a)
	for name, field := range map[string]string{
		"mismatched field": "not-the-cookie-value",
		"missing field":    "",
	} {
		form := validLoginForm()
		if field != "" {
			form.Set("csrf_token", field)
		}
		rec := postAuthorize(a, form, cookie)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: want 403, got %d body %s", name, rec.Code, rec.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s: CSRF failure must not redirect, got Location %s", name, loc)
		}
	}
}

func TestAuthorizePostRejectsBadClientWithoutRedirect(t *testing.T) {
	a := newAuthorizeForTest(t)
	// Same five invalid param sets as the GET variant — no-redirect invariant
	// must hold when validation failure arrives via POST body.
	for _, q := range []string{
		"client_id=ghost&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fevil%2Fcb&response_type=code&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=token&code_challenge=c&code_challenge_method=S256",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code",
		"client_id=atlas&redirect_uri=https%3A%2F%2Fa%2Fcb&response_type=code&code_challenge=c&code_challenge_method=plain",
	} {
		vals, err := url.ParseQuery(q)
		if err != nil {
			t.Fatalf("bad query string %q: %v", q, err)
		}
		req := httptest.NewRequest("POST", "/authorize", strings.NewReader(vals.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("query %q: want 400, got %d", q, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("query %q: must not redirect on validation failure, got Location %s", q, loc)
		}
	}
}
