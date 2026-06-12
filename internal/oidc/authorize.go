package oidc

import (
	_ "embed"
	"html/template"
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
	ClientID, RedirectURI, State, CodeChallenge, Error string
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
		u, err := a.humans.VerifyHumanPassword(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
		if err != nil {
			p.Error = "login failed — check your user id and password"
			a.render(w, http.StatusUnauthorized, p)
			return
		}
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
	_ = loginTmpl.Execute(w, p)
}
