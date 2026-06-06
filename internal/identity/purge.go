package identity

import (
	"context"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// ScopeOrgPurge is the capability that authorizes a pillar's self-org purge
// (org wipe). It is minted ONLY into herald's ephemeral purge token and is
// never granted to a normal agent.
const ScopeOrgPurge = "org:purge"

// DeleteOrg removes an org and all its data from herald's store.
func (svc *Service) DeleteOrg(ctx context.Context, orgID string) error {
	return svc.store.DeleteOrg(ctx, orgID)
}

// ListOrgs returns all orgs (for the reaper's orphan discovery).
func (svc *Service) ListOrgs(ctx context.Context) ([]store.Org, error) {
	return svc.store.ListOrgs(ctx)
}
