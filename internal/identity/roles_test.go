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

// ExpandScopes turns role:<name> entries into their bundle scopes, passes plain
// scopes through, dedups, and fails on an unknown role.
func TestExpandScopes(t *testing.T) {
	owner, _ := identity.ScopesForRole(identity.RoleOrgOwner)

	got, err := identity.ExpandScopes([]string{"role:org-owner", "knowledge:read"})
	if err != nil {
		t.Fatalf("expand: %v", err)
	}
	// Every org-owner scope is present, plus the plain one, with no duplicates
	// (knowledge:read appears in the bundle AND was passed explicitly).
	for _, s := range owner {
		if !hasScope(got, s) {
			t.Fatalf("expanded set missing bundle scope %q: %v", s, got)
		}
	}
	if !hasScope(got, "knowledge:read") {
		t.Fatalf("expanded set missing plain scope: %v", got)
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s]++
		if seen[s] > 1 {
			t.Fatalf("duplicate scope %q in %v", s, got)
		}
	}

	if _, err := identity.ExpandScopes([]string{"role:does-not-exist"}); err == nil {
		t.Fatal("expanding an unknown role must error")
	}

	// nil/empty in, empty out, no error.
	if out, err := identity.ExpandScopes(nil); err != nil || len(out) != 0 {
		t.Fatalf("ExpandScopes(nil) = %v, %v", out, err)
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
