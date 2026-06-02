package grpcadmin

import (
	"context"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
)

// SeedConfig configures genesis — the admin (administration) org + its platform-
// admin owner, provisioned at DEPLOY TIME from a secret. The binary ships no
// default account and no default password: the owner password MUST be supplied
// (from a k8s Secret); only the well-known names default.
type SeedConfig struct {
	AdminOrgName     string // the administration org, e.g. "cwb-admin"
	OwnerDisplayName string // the platform-admin owner, e.g. "cwadmin@carriedworld.com"
	OwnerPassword    string // from a deploy secret; empty => genesis is skipped
}

// Seed idempotently provisions the admin org + its platform-admin owner. If the
// admin org already exists it is a no-op (no credential reset). Returns the
// owner's user id (log it for login). With an empty password and no existing
// admin org it returns an error so the operator knows to supply the secret;
// callers may treat that as a warn-and-continue during the transition.
func Seed(ctx context.Context, id adminapi.Identity, cfg SeedConfig) (ownerID string, err error) {
	if cfg.AdminOrgName == "" || cfg.OwnerDisplayName == "" {
		return "", fmt.Errorf("genesis: AdminOrgName and OwnerDisplayName required")
	}
	// Idempotency: if the admin org already exists, assume seeded — never reset.
	orgs, err := id.ListOrgs(ctx)
	if err != nil {
		return "", fmt.Errorf("genesis: list orgs: %w", err)
	}
	for _, o := range orgs {
		if o.Name == cfg.AdminOrgName {
			return "", nil // already seeded
		}
	}
	if cfg.OwnerPassword == "" {
		return "", fmt.Errorf("genesis: admin org %q absent but no owner password supplied — set the genesis secret to seed", cfg.AdminOrgName)
	}
	org, err := id.CreateOrg(ctx, cfg.AdminOrgName)
	if err != nil {
		return "", fmt.Errorf("genesis: create admin org: %w", err)
	}
	owner, err := id.CreateHuman(ctx, org.ID, cfg.OwnerDisplayName)
	if err != nil {
		return "", fmt.Errorf("genesis: create owner: %w", err)
	}
	// Self-grant platform-admin (grantedBy must be an FK-valid user id; at
	// genesis the owner is the only principal, so it grants to itself).
	if err := id.GrantScope(ctx, owner.ID, ScopePlatformAdmin, owner.ID); err != nil {
		return "", fmt.Errorf("genesis: grant platform-admin: %w", err)
	}
	if err := id.SetHumanPassword(ctx, owner.ID, cfg.OwnerPassword); err != nil {
		return "", fmt.Errorf("genesis: set owner password: %w", err)
	}
	return owner.ID, nil
}
