package oidc

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"html/template"
	"log"
	"net/http"
	"net/url"
)

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// Authorize implements the OAuth2 authorization endpoint (RFC 6749 §3.1) with
// mandatory S256 PKCE: GET renders the herald-hosted login form; POST verifies
// the password and redirects back to the client with a single-use code.
type Authorize struct {
	clients *ClientRegistry
	codes   *CodeStore
	humans  HumanResolver
}

// NewAuthorize wires the authorization endpoint.
func NewAuthorize(clients *ClientRegistry, codes *CodeStore, humans HumanResolver) *Authorize {
	return &Authorize{clients: clients, codes: codes, humans: humans}
}

type loginPage struct {
	ClientID, RedirectURI, State, CodeChallenge, CSRFToken, Error string
}

// csrfCookieName carries the double-submit CSRF token for the login form.
// The __Host- prefix binds the cookie to this origin: it requires Secure,
// Path=/ and no Domain attribute — keep all three exactly as set below.
const csrfCookieName = "__Host-herald_authz_csrf"

// issueCSRF mints a login CSRF token, sets it as a short-lived cookie, and
// returns it for embedding in the form (double-submit pattern — herald keeps
// no server-side login session to bind a token to).
func issueCSRF(w http.ResponseWriter) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails on Linux/macOS/Windows; blank-discard intentional (see refresh.go)
	token := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: token, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	return token
}

// expireCSRF clears the CSRF cookie — each token is single-use.
func expireCSRF(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookieName, Value: "", Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// validate checks the OAuth params shared by GET and POST. Failures return a
// human-readable message and MUST render 400 — never redirect: an unvalidated
// redirect_uri is an open redirect.
func (a *Authorize) validate(q url.Values) (loginPage, string) {
	p := loginPage{
		ClientID:      q.Get("client_id"),
		RedirectURI:   q.Get("redirect_uri"),
		State:         q.Get("state"),
		CodeChallenge: q.Get("code_challenge"),
	}
	if q.Get("response_type") != "code" {
		return p, "response_type must be 'code'"
	}
	if err := a.clients.ValidateRedirect(p.ClientID, p.RedirectURI); err != nil {
		return p, "unknown client or unregistered redirect_uri"
	}
	if p.CodeChallenge == "" || q.Get("code_challenge_method") != "S256" {
		return p, "PKCE required: code_challenge + code_challenge_method=S256"
	}
	return p, ""
}

func (a *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p, msg := a.validate(r.URL.Query())
		if msg != "" {
			http.Error(w, "invalid authorization request: "+msg, http.StatusBadRequest)
			return
		}
		// Idempotent CSRF issue: duplicate GETs (browser prerender, a second
		// tab) must not overwrite the cookie an earlier-rendered form is
		// still paired with, or that form's submit fails the double-submit
		// check. Reuse the inbound token; only mint when absent.
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
			p.CSRFToken = c.Value
		} else {
			p.CSRFToken = issueCSRF(w)
		}
		a.render(w, http.StatusOK, p)
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "unparseable form", http.StatusBadRequest)
			return
		}
		p, msg := a.validate(r.Form)
		if msg != "" {
			http.Error(w, "invalid authorization request: "+msg, http.StatusBadRequest)
			return
		}
		// CSRF double-submit check: the cookie set on GET must match the
		// hidden form field, before any credential is examined. Failures are
		// a plain 403 — never a redirect.
		cookie, err := r.Cookie(csrfCookieName)
		field := r.Form.Get("csrf_token")
		if err != nil || cookie.Value == "" || field == "" ||
			subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(field)) != 1 {
			http.Error(w, "csrf validation failed", http.StatusForbidden)
			return
		}
		u, err := a.humans.VerifyHumanPassword(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
		if err != nil {
			p.Error = "login failed — check your user id and password"
			// Tokens are single-use: rotate the cookie + field for the retry.
			p.CSRFToken = issueCSRF(w)
			a.render(w, http.StatusOK, p)
			return
		}
		expireCSRF(w) // single-use: consumed by the successful login
		code := a.codes.Issue(PendingAuth{
			ClientID: p.ClientID, RedirectURI: p.RedirectURI,
			UserID: u.ID, CodeChallenge: p.CodeChallenge,
		})
		redirect, _ := url.Parse(p.RedirectURI) // validated above
		q := redirect.Query()
		q.Set("code", code)
		if p.State != "" {
			q.Set("state", p.State)
		}
		redirect.RawQuery = q.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *Authorize) render(w http.ResponseWriter, status int, p loginPage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, p); err != nil {
		log.Printf("oidc: authorize: template execute: %v", err)
	}
}
