package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newSvc(t *testing.T) (*identity.Service, store.Store) {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return identity.New(s), s
}

func TestProducts_DefaultAllEnabled(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	m, err := svc.Products(ctx, org.ID)
	if err != nil {
		t.Fatalf("Products: %v", err)
	}
	for _, p := range identity.CanonicalProducts {
		if !m[p] {
			t.Fatalf("default %s should be enabled", p)
		}
	}
	en, _ := svc.EnabledProducts(ctx, org.ID)
	if len(en) != len(identity.CanonicalProducts) {
		t.Fatalf("EnabledProducts default = %v, want all", en)
	}
}

func TestProducts_EnableDisableRoundTrip(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	if err := svc.DisableProduct(ctx, org.ID, identity.ProductCairn); err != nil {
		t.Fatalf("DisableProduct: %v", err)
	}
	en, _ := svc.EnabledProducts(ctx, org.ID)
	if got := join(en); got != "ledger,commonplace" {
		t.Fatalf("after disabling cairn, enabled = %q, want ledger,commonplace", got)
	}
	if err := svc.EnableProduct(ctx, org.ID, identity.ProductCairn); err != nil {
		t.Fatalf("EnableProduct: %v", err)
	}
	en, _ = svc.EnabledProducts(ctx, org.ID)
	if got := join(en); got != "cairn,ledger,commonplace" {
		t.Fatalf("after re-enable, enabled = %q", got)
	}
}

func TestProducts_UnknownProduct(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	if err := svc.EnableProduct(ctx, org.ID, "bogus"); !errors.Is(err, identity.ErrUnknownProduct) {
		t.Fatalf("EnableProduct(bogus) err = %v, want ErrUnknownProduct", err)
	}
}

func TestProducts_MissingOrg(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	if err := svc.DisableProduct(ctx, "no-such-org", identity.ProductCairn); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("DisableProduct(missing org) err = %v, want ErrNotFound", err)
	}
}

func TestCreateOrgWithProducts_ExplicitSubset(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	org, err := svc.CreateOrgWithProducts(ctx, "acme", []string{identity.ProductCairn})
	if err != nil {
		t.Fatalf("CreateOrgWithProducts: %v", err)
	}
	m, _ := svc.Products(ctx, org.ID)
	if !m[identity.ProductCairn] || m[identity.ProductLedger] || m[identity.ProductCommonplace] {
		t.Fatalf("subset {cairn} got %+v", m)
	}
}

func TestCreateOrgWithProducts_UnknownNameCreatesNothing(t *testing.T) {
	svc, _ := newSvc(t)
	ctx := context.Background()
	if _, err := svc.CreateOrgWithProducts(ctx, "acme", []string{"bogus"}); !errors.Is(err, identity.ErrUnknownProduct) {
		t.Fatalf("err = %v, want ErrUnknownProduct", err)
	}
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
