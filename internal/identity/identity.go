// Package identity is herald's domain layer over the store: creating humans
// and agents, computing casket fingerprints, scope grants, and the
// liveness/block cascade. The store is dumb CRUD; this layer holds the rules.
//
// MVP rules (spec §2/§9):
//   - An agent's responsible party must be a HUMAN in the SAME org. Spawned
//     subagent chains (agent-owns-agent) are deferred.
//   - Blocking a human cascades DOWN to its agents (IsActive returns false).
//     Blocking an agent does NOT cascade up. One level only for MVP.
//   - Agent capability (scopes) is independent of its human's — granted here,
//     not derived. (No subset relationship.)
package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// Service is herald's identity domain logic over a store.Store.
type Service struct {
	store store.Store
}

// New constructs a Service.
func New(s store.Store) *Service { return &Service{store: s} }

// CreateOrg creates a new org.
func (svc *Service) CreateOrg(ctx context.Context, name string) (store.Org, error) {
	if name == "" {
		return store.Org{}, errors.New("identity: org name required")
	}
	return svc.store.CreateOrg(ctx, name)
}

// CreateHuman creates a human user in the org.
func (svc *Service) CreateHuman(ctx context.Context, orgID, displayName string) (store.User, error) {
	if displayName == "" {
		return store.User{}, errors.New("identity: display name required")
	}
	if _, err := svc.store.GetOrg(ctx, orgID); err != nil {
		return store.User{}, fmt.Errorf("identity.CreateHuman: org: %w", err)
	}
	return svc.store.CreateUser(ctx, store.User{
		OrgID:       orgID,
		Kind:        store.KindHuman,
		DisplayName: displayName,
	})
}

// CreateAgent creates an agent owned by (responsible to) the given human, in
// the same org, registering its casket public key. responsibleHuman MUST be a
// human in orgID. The agent's fingerprint is computed from pub.
func (svc *Service) CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error) {
	if displayName == "" {
		return store.User{}, errors.New("identity: display name required")
	}
	if len(pub) != ed25519.PublicKeySize {
		return store.User{}, fmt.Errorf("identity: casket pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	human, err := svc.store.GetUser(ctx, responsibleHuman)
	if err != nil {
		return store.User{}, fmt.Errorf("identity.CreateAgent: responsible human: %w", err)
	}
	if human.Kind != store.KindHuman {
		return store.User{}, errors.New("identity.CreateAgent: responsible party must be a human (spawned-subagent chains are deferred)")
	}
	if human.OrgID != orgID {
		return store.User{}, errors.New("identity.CreateAgent: responsible human must be in the same org")
	}
	return svc.store.CreateUser(ctx, store.User{
		OrgID:             orgID,
		Kind:              store.KindAgent,
		DisplayName:       displayName,
		CasketPubkey:      []byte(pub),
		CasketFingerprint: Fingerprint(pub),
		ResponsibleHuman:  responsibleHuman,
	})
}

// GetUser returns a user by id.
func (svc *Service) GetUser(ctx context.Context, id string) (store.User, error) {
	return svc.store.GetUser(ctx, id)
}

// GetAgentByFingerprint resolves an agent from its casket fingerprint — the
// agent-auth path uses this to find the registered pubkey.
func (svc *Service) GetAgentByFingerprint(ctx context.Context, fp string) (store.User, error) {
	return svc.store.GetUserByCasketFingerprint(ctx, fp)
}

// GrantScope grants a capability to a user, recording the granter.
func (svc *Service) GrantScope(ctx context.Context, userID, scope, grantedBy string) error {
	_, err := svc.store.GrantScope(ctx, userID, scope, grantedBy)
	return err
}

// RevokeScope removes a capability from a user.
func (svc *Service) RevokeScope(ctx context.Context, userID, scope string) error {
	return svc.store.RevokeScope(ctx, userID, scope)
}

// EffectiveScopes returns the user's granted scopes.
func (svc *Service) EffectiveScopes(ctx context.Context, userID string) ([]string, error) {
	return svc.store.ListScopes(ctx, userID)
}

// BlockUser blocks a user. Blocking a human cascades to its agents via
// IsActive (no row rewrite needed — the cascade is evaluated on read).
func (svc *Service) BlockUser(ctx context.Context, id string) error {
	return svc.store.SetUserStatus(ctx, id, store.StatusBlocked)
}

// UnblockUser restores a user to active.
func (svc *Service) UnblockUser(ctx context.Context, id string) error {
	return svc.store.SetUserStatus(ctx, id, store.StatusActive)
}

// IsActive reports whether the user may authenticate. An agent is active only
// if it is itself active AND its responsible human is active AND its org is
// active — this is the block cascade evaluated on read (DOWN only: a human's
// block darkens its agents; an agent's block never touches its human). One
// level for MVP; deep spawn-trees are deferred.
func (svc *Service) IsActive(ctx context.Context, id string) bool {
	u, err := svc.store.GetUser(ctx, id)
	if err != nil || u.Status != store.StatusActive {
		return false
	}
	if org, err := svc.store.GetOrg(ctx, u.OrgID); err != nil || org.Status != store.StatusActive {
		return false
	}
	if u.Kind == store.KindAgent && u.ResponsibleHuman != "" {
		h, err := svc.store.GetUser(ctx, u.ResponsibleHuman)
		if err != nil || h.Status != store.StatusActive {
			return false
		}
	}
	return true
}
