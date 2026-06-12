package grpcadmin

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/issuer"
	heraldoidc "github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeTokens/fakePurger satisfy the interfaces New() needs; only DeleteOrg uses
// them and these tests don't exercise the pillar fan-out.
type fakeTokens struct{}

func (fakeTokens) VerifyToken(string) (map[string]any, error) { return nil, nil }
func (fakeTokens) SignToken(map[string]any) (string, error)   { return "tok", nil }

type fakePurger struct{}

func (fakePurger) PurgeOrg(context.Context, string, string) (map[string]string, error) {
	return map[string]string{}, nil
}

func newID(t *testing.T) Identity {
	t.Helper()
	svc, _ := newIdentityStore(t)
	return svc
}

func newIdentityStore(t *testing.T) (*identity.Service, store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return identity.New(st), st
}

func code(err error) codes.Code { return status.Code(err) }

// --- genesis ---

func TestSeed(t *testing.T) {
	id := newID(t)
	ctx := context.Background()
	cfg := SeedConfig{AdminOrgName: "cwb-admin", OwnerDisplayName: "cwadmin@carriedworld.com", OwnerPassword: "supersecret1"}

	ownerID, err := Seed(ctx, id, cfg)
	if err != nil || ownerID == "" {
		t.Fatalf("Seed: id=%q err=%v", ownerID, err)
	}
	// owner holds platform-admin
	scopes, _ := id.EffectiveScopes(ctx, ownerID)
	found := false
	for _, s := range scopes {
		if s == ScopePlatformAdmin {
			found = true
		}
	}
	if !found {
		t.Errorf("owner scopes = %v, want %s", scopes, ScopePlatformAdmin)
	}
	// The admin org is control-plane-only: every product must be disabled so
	// admin accounts structurally can't use cwb products.
	adminOrgID := ""
	orgs, _ := id.ListOrgs(ctx)
	for _, o := range orgs {
		if o.Name == cfg.AdminOrgName {
			adminOrgID = o.ID
		}
	}
	assertAllProductsDisabled := func(when string) {
		prods, err := id.Products(ctx, adminOrgID)
		if err != nil {
			t.Fatalf("Products(%s): %v", when, err)
		}
		for p, enabled := range prods {
			if enabled {
				t.Errorf("admin org product %q enabled %s, want disabled", p, when)
			}
		}
	}
	assertAllProductsDisabled("after first seed")

	// idempotent: second seed is a no-op (still "") and leaves products disabled
	id2, err := Seed(ctx, id, cfg)
	if err != nil || id2 != "" {
		t.Errorf("second Seed = %q, %v; want \"\", nil (no-op)", id2, err)
	}
	assertAllProductsDisabled("after idempotent re-seed")
	// no password + absent org → error (so the operator knows to supply the secret)
	if _, err := Seed(ctx, newID(t), SeedConfig{AdminOrgName: "x", OwnerDisplayName: "y@z"}); err == nil {
		t.Error("Seed with no password + absent org should error")
	}
}

// --- gRPC authz matrix (bufconn) ---

func dialServers(t *testing.T, id Identity) heraldv1.AdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	New(id, fakeTokens{}, fakePurger{}).Register(g)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return heraldv1.NewAdminServiceClient(conn)
}

func md(subject, org, scopes string) context.Context {
	return metadata.NewOutgoingContext(context.Background(),
		metadata.Pairs("cwb-subject", subject, "cwb-org", org, "cwb-scopes", scopes))
}

func TestCreateOrgAuthz(t *testing.T) {
	c := dialServers(t, newID(t))

	// platform-admin → ok
	if _, err := c.CreateOrg(md("owner", "cwb-admin", ScopePlatformAdmin), &heraldv1.CreateOrgRequest{Name: "acme"}); err != nil {
		t.Fatalf("platform-admin CreateOrg: %v", err)
	}
	// no identity → Unauthenticated
	if _, err := c.CreateOrg(context.Background(), &heraldv1.CreateOrgRequest{Name: "x"}); code(err) != codes.Unauthenticated {
		t.Errorf("no-identity = %v, want Unauthenticated", code(err))
	}
	// org-admin (not platform) → PermissionDenied
	if _, err := c.CreateOrg(md("u", "acme", ScopeOrgAdmin), &heraldv1.CreateOrgRequest{Name: "x"}); code(err) != codes.PermissionDenied {
		t.Errorf("org-admin CreateOrg = %v, want PermissionDenied", code(err))
	}
}

func TestOrgScopedAuthz(t *testing.T) {
	id := newID(t)
	ctx := context.Background()
	org, err := id.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	c := dialServers(t, id)

	// org-admin of acme → GetProducts(acme) ok
	if _, err := c.GetProducts(md("u", org.ID, ScopeOrgAdmin), &heraldv1.GetProductsRequest{Org: org.ID}); err != nil {
		t.Fatalf("org-admin GetProducts(own): %v", err)
	}
	// org-admin of a DIFFERENT org → PermissionDenied
	if _, err := c.GetProducts(md("u", "other-org", ScopeOrgAdmin), &heraldv1.GetProductsRequest{Org: org.ID}); code(err) != codes.PermissionDenied {
		t.Errorf("cross-org GetProducts = %v, want PermissionDenied", code(err))
	}
	// platform-admin → any org ok
	if _, err := c.GetProducts(md("o", "cwb-admin", ScopePlatformAdmin), &heraldv1.GetProductsRequest{Org: org.ID}); err != nil {
		t.Errorf("platform-admin GetProducts(any): %v", err)
	}
}

func TestRegisterIssuerAuthz(t *testing.T) {
	id := newID(t)
	ctx := context.Background()
	org, _ := id.CreateOrg(ctx, "acme")
	c := dialServers(t, id)

	resp, err := c.RegisterIssuer(md("u", org.ID, ScopeOrgAdmin), &heraldv1.RegisterIssuerRequest{
		Org:  org.ID,
		Kind: "k8s",
		Ref:  "cluster-a",
	})
	if err != nil {
		t.Fatalf("org-admin RegisterIssuer(own): %v", err)
	}
	if resp.Issuer.GetOrg() != org.ID || resp.Issuer.GetKind() != "k8s" || resp.Issuer.GetRef() != "cluster-a" {
		t.Fatalf("issuer = %+v", resp.Issuer)
	}
	if _, err := c.RegisterIssuer(context.Background(), &heraldv1.RegisterIssuerRequest{Org: org.ID, Kind: "k8s", Ref: "x"}); code(err) != codes.Unauthenticated {
		t.Errorf("no-identity RegisterIssuer = %v, want Unauthenticated", code(err))
	}
	if _, err := c.RegisterIssuer(md("u", "other-org", ScopeOrgAdmin), &heraldv1.RegisterIssuerRequest{Org: org.ID, Kind: "k8s", Ref: "x"}); code(err) != codes.PermissionDenied {
		t.Errorf("cross-org RegisterIssuer = %v, want PermissionDenied", code(err))
	}
	if _, err := c.RegisterIssuer(md("o", "cwb-admin", ScopePlatformAdmin), &heraldv1.RegisterIssuerRequest{Org: org.ID, Kind: "k8s", Ref: "cluster-b"}); err != nil {
		t.Errorf("platform-admin RegisterIssuer(any): %v", err)
	}
}

func TestEnrollFederatedIdentityAuthzAndUniqueness(t *testing.T) {
	id := newID(t)
	ctx := context.Background()
	org, _ := id.CreateOrg(ctx, "acme")
	c := dialServers(t, id)
	iss, err := c.RegisterIssuer(md("u", org.ID, ScopeOrgAdmin), &heraldv1.RegisterIssuerRequest{Org: org.ID, Kind: "k8s", Ref: "cluster"})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	req := &heraldv1.EnrollFederatedIdentityRequest{
		Org:         org.ID,
		DisplayName: "runner",
		IssuerId:    iss.Issuer.GetId(),
		Subject:     "system:serviceaccount:build:runner",
	}

	resp, err := c.EnrollFederatedIdentity(md("u", org.ID, ScopeOrgAdmin), req)
	if err != nil {
		t.Fatalf("org-admin EnrollFederatedIdentity(own): %v", err)
	}
	if resp.Identity.GetOrg() != org.ID || resp.Identity.GetKind() != string(store.KindAgent) || resp.Identity.GetDisplayName() != "runner" {
		t.Fatalf("identity = %+v", resp.Identity)
	}
	if _, err := c.EnrollFederatedIdentity(context.Background(), req); code(err) != codes.Unauthenticated {
		t.Errorf("no-identity EnrollFederatedIdentity = %v, want Unauthenticated", code(err))
	}
	if _, err := c.EnrollFederatedIdentity(md("u", "other-org", ScopeOrgAdmin), req); code(err) != codes.PermissionDenied {
		t.Errorf("cross-org EnrollFederatedIdentity = %v, want PermissionDenied", code(err))
	}
	if _, err := c.EnrollFederatedIdentity(md("u", org.ID, ScopeOrgAdmin), req); code(err) != codes.AlreadyExists {
		t.Errorf("duplicate EnrollFederatedIdentity = %v, want AlreadyExists", code(err))
	}
}

type verifierFunc func(context.Context, string) (string, error)

func (f verifierFunc) Verify(ctx context.Context, attestation string) (string, error) {
	return f(ctx, attestation)
}

func newOIDCProvider(t *testing.T) *heraldoidc.Provider {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	p, err := heraldoidc.NewProvider(heraldoidc.Config{Issuer: "https://herald.test/", SigningKey: priv})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func postFederated(t *testing.T, tokenURL, orgID, issuerID, attestation string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":  {"urn:cwb:params:oauth:grant-type:federated"},
		"org_id":      {orgID},
		"issuer_id":   {issuerID},
		"attestation": {attestation},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestAdminFederatedIdentitySetupIssuesFederatedGrantToken(t *testing.T) {
	id, st := newIdentityStore(t)
	c := dialServers(t, id)
	adminCtx := md("owner", "cwb-admin", ScopePlatformAdmin)

	orgResp, err := c.CreateOrg(adminCtx, &heraldv1.CreateOrgRequest{Name: "acme"})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	orgID := orgResp.Org.GetId()
	issResp, err := c.RegisterIssuer(adminCtx, &heraldv1.RegisterIssuerRequest{
		Org:  orgID,
		Kind: "k8s",
		Ref:  "cluster",
	})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	const subject = "system:serviceaccount:build:runner"
	enrolled, err := c.EnrollFederatedIdentity(adminCtx, &heraldv1.EnrollFederatedIdentityRequest{
		Org:         orgID,
		DisplayName: "runner",
		IssuerId:    issResp.Issuer.GetId(),
		Subject:     subject,
	})
	if err != nil {
		t.Fatalf("EnrollFederatedIdentity: %v", err)
	}

	p := newOIDCProvider(t)
	reg := issuer.NewRegistry()
	reg.Register(issResp.Issuer.GetId(), verifierFunc(func(context.Context, string) (string, error) {
		return subject, nil
	}))
	p.SetTokenHandler(heraldoidc.NewGrantMux(
		heraldoidc.NewAgentGrant(p, id, nil),
		heraldoidc.NewHumanGrant(p, id, nil),
		heraldoidc.NewRefreshGrant(p, id, nil),
		nil,
		heraldoidc.NewFederatedGrant(p, id, st, reg, nil),
	))
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)

	resp, body := postFederated(t, srv.URL+"/token", orgID, issResp.Issuer.GetId(), "sa-token")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%+v", resp.StatusCode, body)
	}
	tok, _ := body["access_token"].(string)
	claims, err := p.VerifyToken(tok)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims["sub"] != enrolled.Identity.GetId() || claims["org"] != orgID || claims["kind"] != string(store.KindAgent) {
		t.Fatalf("claims = %+v; want sub=%s org=%s kind=%s", claims, enrolled.Identity.GetId(), orgID, store.KindAgent)
	}
}

// --- by-fingerprint (internal, no identity) ---

func TestGetAgentByFingerprint(t *testing.T) {
	id := newID(t)
	ctx := context.Background()
	org, _ := id.CreateOrg(ctx, "acme")
	human, err := id.CreateHuman(ctx, org.ID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(nil)
	agent, err := id.CreateAgent(ctx, org.ID, "builder", human.ID, pub)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	g := grpc.NewServer()
	New(id, fakeTokens{}, fakePurger{}).Register(g)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	conn, _ := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { _ = conn.Close() })
	ac := heraldv1.NewAgentServiceClient(conn)

	// No cwb-* identity required (mTLS-internal in prod).
	resp, err := ac.GetAgentByFingerprint(context.Background(), &heraldv1.GetAgentByFingerprintRequest{Fingerprint: agent.CasketFingerprint})
	if err != nil {
		t.Fatalf("GetAgentByFingerprint: %v", err)
	}
	if resp.Agent.GetId() != agent.ID || resp.Agent.GetOrg() != org.ID {
		t.Errorf("agent = %+v, want id=%s org=%s", resp.Agent, agent.ID, org.ID)
	}
	// unknown fingerprint → NotFound
	if _, err := ac.GetAgentByFingerprint(context.Background(), &heraldv1.GetAgentByFingerprintRequest{Fingerprint: "nope"}); code(err) != codes.NotFound {
		t.Errorf("unknown fp = %v, want NotFound", code(err))
	}
}
