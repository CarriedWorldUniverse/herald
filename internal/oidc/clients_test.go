package oidc

import "testing"

func TestParseClients(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
		check   func(t *testing.T, r *ClientRegistry)
	}{
		{name: "empty yields empty registry", in: "", check: func(t *testing.T, r *ClientRegistry) {
			if _, ok := r.Lookup("atlas"); ok {
				t.Fatal("empty registry should have no clients")
			}
		}},
		{name: "single client", in: "atlas|https://atlas.tail41686e.ts.net/oauth/callback", check: func(t *testing.T, r *ClientRegistry) {
			c, ok := r.Lookup("atlas")
			if !ok || c.RedirectURI != "https://atlas.tail41686e.ts.net/oauth/callback" {
				t.Fatalf("got %+v ok=%v", c, ok)
			}
		}},
		{name: "two clients", in: "atlas|https://a/cb,other|https://b/cb", check: func(t *testing.T, r *ClientRegistry) {
			if _, ok := r.Lookup("other"); !ok {
				t.Fatal("missing second client")
			}
		}},
		{name: "malformed entry", in: "atlas-no-pipe", wantErr: true},
		{name: "non-https redirect rejected", in: "atlas|http://evil/cb", wantErr: true},
		{name: "localhost http allowed for dev", in: "dev|http://localhost:8443/cb", check: func(t *testing.T, r *ClientRegistry) {
			if _, ok := r.Lookup("dev"); !ok {
				t.Fatal("localhost http should be allowed")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ParseClients(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, r)
		})
	}
}

func TestValidateRedirect(t *testing.T) {
	r, _ := ParseClients("atlas|https://a/cb")
	if err := r.ValidateRedirect("atlas", "https://a/cb"); err != nil {
		t.Fatalf("exact match should pass: %v", err)
	}
	if err := r.ValidateRedirect("atlas", "https://a/cb?extra=1"); err == nil {
		t.Fatal("non-exact redirect must be rejected")
	}
	if err := r.ValidateRedirect("ghost", "https://a/cb"); err == nil {
		t.Fatal("unknown client must be rejected")
	}
}
