package identity_test

import (
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
)

// Every shipped role must resolve to a non-empty scope set, and an unknown role
// must report ok=false (so onboarding fails loudly on a typo'd role name).
func TestScopesForRole_KnownAndUnknown(t *testing.T) {
	for _, r := range identity.Roles() {
		scopes, ok := identity.ScopesForRole(r)
		if !ok {
			t.Fatalf("role %q reported unknown", r)
		}
		if len(scopes) == 0 {
			t.Fatalf("role %q resolved to no scopes", r)
		}
	}
	if _, ok := identity.ScopesForRole(identity.Role("nope")); ok {
		t.Fatal("unknown role must report ok=false")
	}
}

// org-owner is the only bundle that may administer the org, so it carries
// herald:org-admin; croft (the managing AI, no human mgmt) must NOT.
func TestRoleBundles_OrgAdminOnlyForOwner(t *testing.T) {
	ownerScopes, _ := identity.ScopesForRole(identity.RoleOrgOwner)
	if !hasScope(ownerScopes, identity.ScopeOrgAdmin) {
		t.Fatalf("org-owner must include %s", identity.ScopeOrgAdmin)
	}
	croftScopes, _ := identity.ScopesForRole(identity.RoleCroft)
	if hasScope(croftScopes, identity.ScopeOrgAdmin) {
		t.Fatalf("croft must NOT include %s (no human mgmt)", identity.ScopeOrgAdmin)
	}
}

// THE safety invariant at the bundle level: no role a tenant can hold may grant
// a control-plane scope. platform-admin is genesis-only and must be unreachable
// through any bundle.
func TestRoleBundles_NoControlPlaneScope(t *testing.T) {
	for _, r := range identity.Roles() {
		scopes, _ := identity.ScopesForRole(r)
		for _, s := range scopes {
			if identity.IsControlPlaneScope(s) {
				t.Fatalf("role %q grants control-plane scope %q — tenant invariant violated", r, s)
			}
		}
	}
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
