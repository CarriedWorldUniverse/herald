package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
)

// The load-bearing tenant invariant: a control-plane scope (platform-admin) may
// be granted only to a principal in the admin org. Granting it to a tenant-org
// principal must fail with identity.ErrControlPlaneScopeForTenant; org-scoped
// scopes are unaffected.
func TestGrantScope_TenantInvariant(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()

	adminOrg, err := svc.CreateOrg(ctx, "cwb-admin")
	if err != nil {
		t.Fatalf("create admin org: %v", err)
	}
	tenantOrg, err := svc.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("create tenant org: %v", err)
	}
	svc.SetAdminOrg(adminOrg.ID)

	adminUser, err := svc.CreateHuman(ctx, adminOrg.ID, "cwadmin@carriedworld.com")
	if err != nil {
		t.Fatalf("create admin human: %v", err)
	}
	tenantUser, err := svc.CreateHuman(ctx, tenantOrg.ID, "alice@acme.test")
	if err != nil {
		t.Fatalf("create tenant human: %v", err)
	}

	// Reject: platform-admin to a tenant-org principal.
	err = svc.GrantScope(ctx, tenantUser.ID, identity.ScopePlatformAdmin, adminUser.ID)
	if !errors.Is(err, identity.ErrControlPlaneScopeForTenant) {
		t.Fatalf("granting platform-admin to a tenant principal: want ErrControlPlaneScopeForTenant, got %v", err)
	}

	// Allow: platform-admin to an admin-org principal.
	if err := svc.GrantScope(ctx, adminUser.ID, identity.ScopePlatformAdmin, adminUser.ID); err != nil {
		t.Fatalf("granting platform-admin to the admin org must succeed, got %v", err)
	}

	// Allow: an org-scoped scope to the tenant principal.
	if err := svc.GrantScope(ctx, tenantUser.ID, identity.ScopeRepoWrite, adminUser.ID); err != nil {
		t.Fatalf("granting an org-scoped scope to a tenant must succeed, got %v", err)
	}
}

// Fail closed: if herald does not know which org is the control plane (admin org
// unset), no platform-admin grant is permitted anywhere.
func TestGrantScope_FailsClosedWhenAdminOrgUnset(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, err := svc.CreateOrg(ctx, "whoever")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	u, err := svc.CreateHuman(ctx, org.ID, "x@y.test")
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	if err := svc.GrantScope(ctx, u.ID, identity.ScopePlatformAdmin, u.ID); !errors.Is(err, identity.ErrControlPlaneScopeForTenant) {
		t.Fatalf("with admin org unset, platform-admin grant must be refused, got %v", err)
	}
}
