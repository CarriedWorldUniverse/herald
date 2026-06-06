package identity_test

import (
	"context"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestServiceDeleteOrgAndListOrgs(t *testing.T) {
	s, _ := store.Open(":memory:")
	t.Cleanup(func() { _ = s.Close() })
	svc := identity.New(s)
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, "acme")
	orgs, err := svc.ListOrgs(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].ID != org.ID {
		t.Fatalf("ListOrgs = %+v, %v", orgs, err)
	}
	if err := svc.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("DeleteOrg: %v", err)
	}
	if _, err := svc.GetOrg(ctx, org.ID); err != store.ErrNotFound {
		t.Fatalf("org should be gone, got %v", err)
	}
}

func TestScopeOrgPurgeConstant(t *testing.T) {
	if identity.ScopeOrgPurge != "org:purge" {
		t.Fatalf("ScopeOrgPurge = %q", identity.ScopeOrgPurge)
	}
}
