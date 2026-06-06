package oidc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/issuer"
	herald "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func federatedStack(t *testing.T) (*herald.Provider, *identity.Service, store.Store, *issuer.Registry, *httptest.Server) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	p := newTestProvider(t)
	reg := issuer.NewRegistry()
	p.SetTokenHandler(herald.NewGrantMux(
		herald.NewAgentGrant(p, svc, nil),
		herald.NewHumanGrant(p, svc, nil),
		herald.NewRefreshGrant(p, svc, nil),
		herald.NewFederatedGrant(p, svc, s, reg, nil),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, svc, s, reg, srv
}

func enrollFederatedAgent(t *testing.T, ctx context.Context, svc *identity.Service, s store.Store, reg *issuer.Registry, orgID, subject string) (store.User, store.Issuer) {
	t.Helper()
	h, err := svc.CreateHuman(ctx, orgID, "owner")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	a, err := s.CreateUser(ctx, store.User{
		OrgID:            orgID,
		Kind:             store.KindAgent,
		DisplayName:      "runner",
		ResponsibleHuman: h.ID,
	})
	if err != nil {
		t.Fatalf("CreateUser agent: %v", err)
	}
	iss, err := s.RegisterIssuer(ctx, store.Issuer{OrgID: orgID, Kind: "k8s", Ref: "cluster"})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	if _, err := s.AddBinding(ctx, store.FederatedBinding{OrgID: orgID, UserID: a.ID, IssuerID: iss.ID, Subject: subject}); err != nil {
		t.Fatalf("AddBinding: %v", err)
	}
	reg.Register(iss.ID, verifierFunc(func(context.Context, string) (string, error) { return subject, nil }))
	return a, iss
}

func postFederated(t *testing.T, tokenURL, orgID, issuerID, attestation string) (*http.Response, map[string]any) {
	t.Helper()
	return postForm(t, tokenURL, url.Values{
		"grant_type":  {"urn:cwb:params:oauth:grant-type:federated"},
		"org_id":      {orgID},
		"issuer_id":   {issuerID},
		"attestation": {attestation},
	})
}

func postForm(t *testing.T, tokenURL string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestFederatedGrant_ValidBindingIssuesToken(t *testing.T) {
	p, svc, s, reg, srv := federatedStack(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	const subject = "system:serviceaccount:build:runner"
	a, iss := enrollFederatedAgent(t, ctx, svc, s, reg, org.ID, subject)
	_ = svc.GrantScope(ctx, a.ID, "repo:write", a.ResponsibleHuman)

	resp, body := postFederated(t, srv.URL+"/token", org.ID, iss.ID, "sa-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%+v", resp.StatusCode, body)
	}
	tok, _ := body["access_token"].(string)
	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["sub"] != a.ID {
		t.Fatalf("sub = %v, want %s", claims["sub"], a.ID)
	}
	if claims["org"] != org.ID || claims["kind"] != "agent" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestFederatedGrant_BlockedUnknownAndCrossOrgRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, p *herald.Provider, svc *identity.Service, s store.Store, reg *issuer.Registry, srv *httptest.Server)
	}{
		{name: "blocked", run: func(t *testing.T, _ *herald.Provider, svc *identity.Service, s store.Store, reg *issuer.Registry, srv *httptest.Server) {
			ctx := context.Background()
			org, _ := svc.CreateOrg(ctx, "acme")
			a, iss := enrollFederatedAgent(t, ctx, svc, s, reg, org.ID, "system:serviceaccount:build:runner")
			if err := svc.BlockUser(ctx, a.ID); err != nil {
				t.Fatalf("BlockUser: %v", err)
			}
			resp, _ := postFederated(t, srv.URL+"/token", org.ID, iss.ID, "sa-token")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", resp.StatusCode)
			}
		}},
		{name: "unknown subject", run: func(t *testing.T, _ *herald.Provider, svc *identity.Service, s store.Store, reg *issuer.Registry, srv *httptest.Server) {
			ctx := context.Background()
			org, _ := svc.CreateOrg(ctx, "acme")
			_, iss := enrollFederatedAgent(t, ctx, svc, s, reg, org.ID, "system:serviceaccount:build:runner")
			reg.Register(iss.ID, verifierFunc(func(context.Context, string) (string, error) {
				return "system:serviceaccount:other:runner", nil
			}))
			resp, _ := postFederated(t, srv.URL+"/token", org.ID, iss.ID, "sa-token")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", resp.StatusCode)
			}
		}},
		{name: "cross org", run: func(t *testing.T, _ *herald.Provider, svc *identity.Service, s store.Store, reg *issuer.Registry, srv *httptest.Server) {
			ctx := context.Background()
			org, _ := svc.CreateOrg(ctx, "acme")
			other, _ := svc.CreateOrg(ctx, "other")
			_, iss := enrollFederatedAgent(t, ctx, svc, s, reg, org.ID, "system:serviceaccount:build:runner")
			resp, _ := postFederated(t, srv.URL+"/token", other.ID, iss.ID, "sa-token")
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", resp.StatusCode)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, svc, s, reg, srv := federatedStack(t)
			tc.run(t, p, svc, s, reg, srv)
		})
	}
}

type verifierFunc func(context.Context, string) (string, error)

func (f verifierFunc) Verify(ctx context.Context, attestation string) (string, error) {
	return f(ctx, attestation)
}
