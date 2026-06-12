package oidc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestAuthorizeGetRendersForm(t *testing.T) {
	a := newAuthorizeForTest(t)
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest("GET", "/authorize?"+authzQuery, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`name="username"`, `name="password"`, `value="xyz"`, `value="abc123"`} {
		if !strings.Contains(body, want) {
			t.Errorf("form missing %s", want)
		}
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
	form := url.Values{
		"client_id": {"atlas"}, "redirect_uri": {"https://a/cb"}, "response_type": {"code"},
		"state": {"xyz"}, "code_challenge": {"abc123"}, "code_challenge_method": {"S256"},
		"username": {"u-good"}, "password": {"pw"},
	}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
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
	form := url.Values{
		"client_id": {"atlas"}, "redirect_uri": {"https://a/cb"}, "response_type": {"code"},
		"code_challenge": {"abc123"}, "code_challenge_method": {"S256"},
		"username": {"u-good"}, "password": {"WRONG"},
	}
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 re-render, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "login failed") {
		t.Error("error message missing from re-rendered form")
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Error("must not redirect on bad login")
	}
}
