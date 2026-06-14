package identity

import (
	"fmt"
	"strings"
)

// Roles and the canonical scope vocabulary. This is herald's policy surface:
// a role is a named bundle of scopes assigned as a unit during onboarding and
// in the console; raw GrantScope remains available for one-off capabilities
// underneath a role. Edit roleScopes to change what a role grants.
//
// The scope constants here are the single source of truth for the platform's
// capability strings; grpcadmin aliases the control-plane ones (it imports this
// package, so the values cannot drift).

// Org-scoped capability scopes the bundles compose. repo:* and knowledge:* are
// what the CWB pillars enforce (cairn, commonplace); herald:org-admin lets a
// principal administer ITS OWN org; agent:create lets it provision sub-agents.
const (
	ScopeRepoRead       = "repo:read"
	ScopeRepoWrite      = "repo:write"
	ScopeKnowledgeRead  = "knowledge:read"
	ScopeKnowledgeWrite = "knowledge:write"
	ScopeAgentCreate    = "agent:create"
	ScopeOrgAdmin       = "herald:org-admin"

	// ScopePlatformAdmin is the cross-org control-plane scope. It is genesis-
	// only: never part of a role bundle, and never grantable to a principal in
	// a non-admin (tenant) org. See ControlPlaneScopes and the GrantScope guard.
	ScopePlatformAdmin = "herald:platform-admin"
)

// Role is a named bundle of scopes.
type Role string

const (
	// RoleOrgOwner administers the org, including its humans and agents.
	RoleOrgOwner Role = "org-owner"
	// RoleCroft is the org's managing AI: broad org-scoped work, no human mgmt.
	RoleCroft Role = "croft"
	// RoleOrgMember works in the org (read+write data), no administration.
	RoleOrgMember Role = "org-member"
	// RoleViewer is read-only.
	RoleViewer Role = "viewer"
)

// orderedRoles is the stable discovery/UX order.
var orderedRoles = []Role{RoleOrgOwner, RoleCroft, RoleOrgMember, RoleViewer}

// roleScopes is the bundle → scopes policy. INVARIANT: no bundle contains a
// ControlPlaneScope — bundles are org-scoped only. roles_test enforces this.
var roleScopes = map[Role][]string{
	RoleOrgOwner: {
		ScopeOrgAdmin,
		ScopeRepoRead, ScopeRepoWrite,
		ScopeKnowledgeRead, ScopeKnowledgeWrite,
		ScopeAgentCreate,
	},
	RoleCroft: {
		ScopeRepoRead, ScopeRepoWrite,
		ScopeKnowledgeRead, ScopeKnowledgeWrite,
		ScopeAgentCreate,
	},
	RoleOrgMember: {
		ScopeRepoRead, ScopeRepoWrite,
		ScopeKnowledgeRead, ScopeKnowledgeWrite,
	},
	RoleViewer: {
		ScopeRepoRead,
		ScopeKnowledgeRead,
	},
}

// ControlPlaneScopes is the set of scopes a tenant principal must never hold —
// they reach across orgs or touch the control plane. A principal in a non-admin
// org cannot be granted any of these (the GrantScope guard enforces it), and no
// role bundle may include one (roles_test enforces it). Keep this the single
// list both checks read from.
var ControlPlaneScopes = []string{ScopePlatformAdmin}

// IsControlPlaneScope reports whether scope is control-plane-restricted.
func IsControlPlaneScope(scope string) bool {
	for _, s := range ControlPlaneScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Roles returns the known role names in stable order.
func Roles() []Role {
	out := make([]Role, len(orderedRoles))
	copy(out, orderedRoles)
	return out
}

// ScopesForRole returns the scopes a role grants (a copy, safe to mutate) and
// whether the role is known.
func ScopesForRole(r Role) ([]string, bool) {
	s, ok := roleScopes[r]
	if !ok {
		return nil, false
	}
	out := make([]string, len(s))
	copy(out, s)
	return out, true
}

// RolePrefix marks a grant entry as a role to expand rather than a raw scope.
// Callers (onboarding, the console) pass "role:org-owner"; ExpandScopes turns it
// into the bundle's scopes so the bundle stays authoritative here in herald.
const RolePrefix = "role:"

// ExpandScopes resolves a grant list: each "role:<name>" entry becomes that
// role's scopes, plain scopes pass through, the result is de-duplicated in
// first-seen order, and an unknown role is an error (onboarding fails loudly on
// a typo). nil/empty in → empty out.
func ExpandScopes(entries []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, e := range entries {
		if name, ok := strings.CutPrefix(e, RolePrefix); ok {
			scopes, known := ScopesForRole(Role(name))
			if !known {
				return nil, fmt.Errorf("identity: unknown role %q", name)
			}
			for _, s := range scopes {
				add(s)
			}
			continue
		}
		add(e)
	}
	return out, nil
}
