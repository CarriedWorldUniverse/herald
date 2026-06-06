package grpcadmin

import (
	"context"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/identity"
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

// Seed idempotently provisions the admin org + its platform-admin owner, and
// ALWAYS disables every product for the admin org. Returns the owner's user id
// on first seed (log it for login), or "" if the admin org already existed (no
// credential reset). With an empty password and no existing admin org it errors
// so the operator knows to supply the secret; callers may treat that as a
// warn-and-continue during the transition.
//
// The admin org is control-plane-only: admin accounts must not be able to USE
// cwb products (cairn/ledger/commonplace) — that's a conflict of interest. We
// disable all products for the admin org via the entitlement deny-list, so the
// gateway's product gate blocks any product call scoped to it regardless of
// scopes. This runs every boot, so a pre-existing admin org is hardened on
// upgrade too.
func Seed(ctx context.Context, id Identity, cfg SeedConfig) (ownerID string, err error) {
	if cfg.AdminOrgName == "" || cfg.OwnerDisplayName == "" {
		return "", fmt.Errorf("genesis: AdminOrgName and OwnerDisplayName required")
	}
	orgs, err := id.ListOrgs(ctx)
	if err != nil {
		return "", fmt.Errorf("genesis: list orgs: %w", err)
	}
	var adminOrgID string
	for _, o := range orgs {
		if o.Name == cfg.AdminOrgName {
			adminOrgID = o.ID // already seeded — don't reset credentials
			break
		}
	}
	if adminOrgID == "" {
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
		adminOrgID = org.ID
		ownerID = owner.ID
	}
	// Always: the admin org is control-plane-only — disable every product
	// (idempotent; hardens both a freshly-created and a pre-existing admin org).
	for _, p := range identity.CanonicalProducts {
		if derr := id.DisableProduct(ctx, adminOrgID, p); derr != nil {
			return ownerID, fmt.Errorf("genesis: disable product %q for admin org: %w", p, derr)
		}
	}
	return ownerID, nil
}
