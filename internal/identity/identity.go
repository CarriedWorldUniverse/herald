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

	"golang.org/x/crypto/bcrypt"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// Service is herald's identity domain logic over a store.Store.
type Service struct {
	store store.Store
}

// New constructs a Service.
func New(s store.Store) *Service { return &Service{store: s} }

// ErrInvalidCredentials is the single, uniform error every human-login failure
// returns — unknown user, not a human, inactive, no password set, or wrong
// password all look identical, so login leaks no user-enumeration signal.
var ErrInvalidCredentials = errors.New("identity: invalid credentials")

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
// the same org, with status Active. Used by the admin-bootstrap path (the
// first agents, before any agent token exists). For self-provisioned agents
// that must await human validation, use CreateAgentPending.
func (svc *Service) CreateAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error) {
	return svc.createAgent(ctx, orgID, displayName, responsibleHuman, pub, store.StatusActive)
}

// CreateAgentPending creates a self-provisioned agent in the Pending state:
// it exists but cannot authenticate until a human validates it (ValidateAgent).
// This is the human-in-the-loop-at-birth gate on self-provisioning.
func (svc *Service) CreateAgentPending(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey) (store.User, error) {
	return svc.createAgent(ctx, orgID, displayName, responsibleHuman, pub, store.StatusPending)
}

func (svc *Service) createAgent(ctx context.Context, orgID, displayName, responsibleHuman string, pub ed25519.PublicKey, status store.Status) (store.User, error) {
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
	fp := Fingerprint(pub)
	if _, err := svc.store.GetUserByCasketFingerprint(ctx, fp); err == nil {
		return store.User{}, store.ErrDuplicateFingerprint
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("identity.createAgent: fingerprint check: %w", err)
	}
	return svc.store.CreateUser(ctx, store.User{
		OrgID:             orgID,
		Kind:              store.KindAgent,
		DisplayName:       displayName,
		Status:            status,
		CasketPubkey:      []byte(pub),
		CasketFingerprint: fp,
		ResponsibleHuman:  responsibleHuman,
	})
}

// ValidateAgent flips a pending agent to active. validatingHuman MUST be the
// agent's responsible human (only the human who answers for the agent may
// ratify it). No-op-safe on an already-active agent. This is the
// human-in-the-loop-at-birth gate.
func (svc *Service) ValidateAgent(ctx context.Context, agentID, validatingHuman string) error {
	agent, err := svc.store.GetUser(ctx, agentID)
	if err != nil {
		return fmt.Errorf("identity.ValidateAgent: %w", err)
	}
	if agent.Kind != store.KindAgent {
		return errors.New("identity.ValidateAgent: not an agent")
	}
	if agent.ResponsibleHuman != validatingHuman {
		return errors.New("identity.ValidateAgent: only the responsible human may validate this agent")
	}
	if agent.Status == store.StatusBlocked {
		return errors.New("identity.ValidateAgent: agent is blocked")
	}
	return svc.store.SetUserStatus(ctx, agentID, store.StatusActive)
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

// SetHumanPassword bcrypt-hashes plaintext and stores it as the human's login
// secret. Errors if the user is not a human.
func (svc *Service) SetHumanPassword(ctx context.Context, userID, plaintext string) error {
	u, err := svc.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.Kind != store.KindHuman {
		return fmt.Errorf("identity.SetHumanPassword: user %s is not a human", userID)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("identity.SetHumanPassword: hash: %w", err)
	}
	return svc.store.SetLoginSecret(ctx, userID, string(hash))
}

// VerifyHumanPassword returns the user iff it is an active human whose stored
// bcrypt hash matches plaintext. Every failure returns ErrInvalidCredentials.
func (svc *Service) VerifyHumanPassword(ctx context.Context, username, plaintext string) (store.User, error) {
	// Resolve by id first (back-compat), then fall back to a unique display-name
	// (email) match — so humans can log in as e.g. cwadmin@carriedworld.com, not
	// only by UUID. Ambiguous/absent both surface as ErrInvalidCredentials.
	u, err := svc.store.GetUser(ctx, username)
	if err != nil {
		u, err = svc.store.GetUserByDisplayName(ctx, username)
		if err != nil {
			return store.User{}, ErrInvalidCredentials
		}
	}
	if u.Kind != store.KindHuman || u.LoginSecret == "" {
		return store.User{}, ErrInvalidCredentials
	}
	if !svc.IsActive(ctx, u.ID) {
		return store.User{}, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.LoginSecret), []byte(plaintext)); err != nil {
		return store.User{}, ErrInvalidCredentials
	}
	return u, nil
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
