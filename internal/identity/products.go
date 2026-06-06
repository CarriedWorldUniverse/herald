package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// Canonical CWB products an org can enable/disable. herald is the core (never
// listed) and interchange is infra. The slice order is the stable claim order.
const (
	ProductCairn       = "cairn"
	ProductLedger      = "ledger"
	ProductCommonplace = "commonplace"
)

// CanonicalProducts is the ordered set of toggleable products.
var CanonicalProducts = []string{ProductCairn, ProductLedger, ProductCommonplace}

// ErrUnknownProduct is returned for a product name outside CanonicalProducts.
var ErrUnknownProduct = errors.New("identity: unknown product")

func isCanonicalProduct(p string) bool {
	for _, c := range CanonicalProducts {
		if c == p {
			return true
		}
	}
	return false
}

// EnableProduct turns a product on for an org.
func (svc *Service) EnableProduct(ctx context.Context, orgID, product string) error {
	return svc.setProduct(ctx, orgID, product, true)
}

// DisableProduct turns a product off for an org (reversible; data untouched).
func (svc *Service) DisableProduct(ctx context.Context, orgID, product string) error {
	return svc.setProduct(ctx, orgID, product, false)
}

func (svc *Service) setProduct(ctx context.Context, orgID, product string, enabled bool) error {
	if !isCanonicalProduct(product) {
		return ErrUnknownProduct
	}
	if _, err := svc.store.GetOrg(ctx, orgID); err != nil {
		return fmt.Errorf("identity.setProduct: org: %w", err)
	}
	return svc.store.SetProductEnabled(ctx, orgID, product, enabled)
}

// GetOrg exposes the store lookup so callers (e.g. adminapi) can verify an org
// exists and get a store.ErrNotFound to map to 404. (Products itself returns an
// all-enabled map for an unknown org, so it cannot be used for existence.)
func (svc *Service) GetOrg(ctx context.Context, orgID string) (store.Org, error) {
	return svc.store.GetOrg(ctx, orgID)
}

// Products returns the full canonical map (product -> enabled), applying the
// deny-list: an absent override row means enabled.
func (svc *Service) Products(ctx context.Context, orgID string) (map[string]bool, error) {
	overrides, err := svc.store.ListProductOverrides(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("identity.Products: %w", err)
	}
	out := make(map[string]bool, len(CanonicalProducts))
	for _, p := range CanonicalProducts {
		enabled, ok := overrides[p]
		if !ok {
			enabled = true // deny-list default
		}
		out[p] = enabled
	}
	return out, nil
}

// EnabledProducts returns the canonical set minus disabled, in canonical order.
func (svc *Service) EnabledProducts(ctx context.Context, orgID string) ([]string, error) {
	m, err := svc.Products(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, p := range CanonicalProducts {
		if m[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// CreateOrgWithProducts creates an org and sets its initial entitlement. A
// nil/empty products slice = all canonical products enabled (writes no rows).
// A non-nil slice enables exactly those; every other canonical product gets an
// explicit disabled row. An unknown name returns ErrUnknownProduct and creates
// no org.
func (svc *Service) CreateOrgWithProducts(ctx context.Context, name string, products []string) (store.Org, error) {
	if products != nil {
		for _, p := range products {
			if !isCanonicalProduct(p) {
				return store.Org{}, ErrUnknownProduct
			}
		}
	}
	org, err := svc.CreateOrg(ctx, name)
	if err != nil {
		return store.Org{}, err
	}
	if products != nil {
		want := map[string]bool{}
		for _, p := range products {
			want[p] = true
		}
		for _, c := range CanonicalProducts {
			if !want[c] {
				if err := svc.store.SetProductEnabled(ctx, org.ID, c, false); err != nil {
					return store.Org{}, fmt.Errorf("CreateOrgWithProducts: disable %s: %w", c, err)
				}
			}
		}
	}
	return org, nil
}
