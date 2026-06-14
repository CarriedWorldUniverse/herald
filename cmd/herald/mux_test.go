package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewHTTPMux_RoutesProviderPaths guards against the class of bug where a
// route exists inside provider.Handler() but is never mounted on herald's outer
// mux (so it 404s in production even though unit tests against provider.Handler()
// pass). Every provider-served path — including /agent/identity — must reach the
// provider handler, not the mux's 404.
func TestNewHTTPMux_RoutesProviderPaths(t *testing.T) {
	var gotProvider, gotAPI bool
	providerH := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { gotProvider = true })
	apiH := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { gotAPI = true })
	mux := newHTTPMux(providerH, apiH)

	providerPaths := []struct {
		method, path string
	}{
		{"GET", "/.well-known/openid-configuration"},
		{"GET", "/.well-known/oauth-authorization-server"},
		{"GET", "/jwks"},
		{"GET", "/authorize"},
		{"POST", "/token"},
		{"POST", "/revoke"},
		{"POST", "/agent/identity"},
	}
	for _, p := range providerPaths {
		gotProvider = false
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(p.method, p.path, nil))
		if rr.Code == http.StatusNotFound {
			t.Errorf("%s %s 404s — not mounted on the outer mux", p.method, p.path)
		}
		if !gotProvider {
			t.Errorf("%s %s did not reach the provider handler", p.method, p.path)
		}
	}

	// /api/ must reach the admin API handler.
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/api/whoami", nil))
	if !gotAPI {
		t.Error("/api/ did not reach the api handler")
	}
}
