package identity_test

import (
	"context"
	"errors"
	"testing"

	casket "github.com/CarriedWorldUniverse/casket-go"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

const testSeed = "owner-seed-32-bytes-padded-xxxxx" // 32 bytes

func newTestIdentity(t *testing.T) *identity.Service {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return identity.New(s)
}

func TestFingerprint_StableAndShort(t *testing.T) {
	_, pub, err := casket.DeriveAgentKey([]byte(testSeed), "anvil")
	if err != nil {
		t.Fatalf("DeriveAgentKey: %v", err)
	}
	fp := identity.Fingerprint(pub)
	if fp == "" {
		t.Fatal("empty fingerprint")
	}
	if identity.Fingerprint(pub) != fp {
		t.Fatal("fingerprint not stable for same key")
	}
	_, pub2, _ := casket.DeriveAgentKey([]byte(testSeed), "maren")
	if identity.Fingerprint(pub2) == fp {
		t.Fatal("different keys must have different fingerprints")
	}
}

func TestCreateAgent_SetsResponsibleHumanAndFingerprint(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")

	a, err := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if a.ResponsibleHuman != h.ID {
		t.Fatalf("responsible human = %q, want %q", a.ResponsibleHuman, h.ID)
	}
	if a.CasketFingerprint != identity.Fingerprint(pub) {
		t.Fatal("fingerprint not set from pubkey")
	}
	if a.Kind != store.KindAgent {
		t.Fatalf("kind = %q", a.Kind)
	}
}

func TestCreateAgent_RejectsNonHumanResponsible(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")
	parent, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	// An agent cannot be the responsible *human* of another agent (MVP:
	// responsible_human must be a human). Spawned-subagent chains are deferred.
	_, pub2, _ := casket.DeriveAgentKey([]byte(testSeed), "worker")
	if _, err := svc.CreateAgent(ctx, org.ID, "worker", parent.ID, pub2); err == nil {
		t.Fatal("expected error: responsible party must be a human")
	}
}

func TestCreateAgent_RejectsCrossOrgResponsible(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	orgA, _ := svc.CreateOrg(ctx, "acme")
	orgB, _ := svc.CreateOrg(ctx, "other")
	h, _ := svc.CreateHuman(ctx, orgA.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")

	// Agent's responsible human must be in the same org.
	if _, err := svc.CreateAgent(ctx, orgB.ID, "anvil", h.ID, pub); err == nil {
		t.Fatal("expected error: responsible human in a different org")
	}
}

func TestBlockHuman_CascadesToAgents(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	if !svc.IsActive(ctx, a.ID) {
		t.Fatal("agent should start active")
	}
	if err := svc.BlockUser(ctx, h.ID); err != nil {
		t.Fatalf("BlockUser: %v", err)
	}
	// Blocking the human must cascade: the agent is no longer active.
	if svc.IsActive(ctx, a.ID) {
		t.Fatal("blocking human must cascade to its agents")
	}
	// Unblocking the human restores the agent.
	if err := svc.UnblockUser(ctx, h.ID); err != nil {
		t.Fatalf("UnblockUser: %v", err)
	}
	if !svc.IsActive(ctx, a.ID) {
		t.Fatal("unblocking human should restore the agent")
	}
}

func TestBlockAgent_DoesNotAffectHuman(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	// Per-agent block is the scalpel: blocking the agent must NOT touch the human.
	if err := svc.BlockUser(ctx, a.ID); err != nil {
		t.Fatalf("BlockUser agent: %v", err)
	}
	if svc.IsActive(ctx, a.ID) {
		t.Fatal("blocked agent should be inactive")
	}
	if !svc.IsActive(ctx, h.ID) {
		t.Fatal("blocking an agent must NOT cascade up to the human")
	}
}

func TestEffectiveScopes(t *testing.T) {
	svc := newTestIdentity(t)
	ctx := context.Background()
	org, _ := svc.CreateOrg(ctx, "acme")
	h, _ := svc.CreateHuman(ctx, org.ID, "jacinta")
	_, pub, _ := casket.DeriveAgentKey([]byte(testSeed), "anvil")
	a, _ := svc.CreateAgent(ctx, org.ID, "anvil", h.ID, pub)

	_ = svc.GrantScope(ctx, a.ID, "repo:write", h.ID)
	_ = svc.GrantScope(ctx, a.ID, "repo:read", h.ID)
	scopes, err := svc.EffectiveScopes(ctx, a.ID)
	if err != nil {
		t.Fatalf("EffectiveScopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("want 2 scopes, got %v", scopes)
	}
}

func TestCreateAgent_DuplicatePubkeyRejected(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()
	svc := identity.New(s)
	org, _ := s.CreateOrg(ctx, "acme")
	human, _ := svc.CreateHuman(ctx, org.ID, "alice")

	_, pub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "builder")
	if _, err := svc.CreateAgent(ctx, org.ID, "builder", human.ID, pub); err != nil {
		t.Fatalf("first agent: %v", err)
	}
	if _, err := svc.CreateAgent(ctx, org.ID, "builder2", human.ID, pub); !errors.Is(err, store.ErrDuplicateFingerprint) {
		t.Fatalf("dup pubkey err = %v, want store.ErrDuplicateFingerprint", err)
	}
	_, pub2, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "reader")
	if _, err := svc.CreateAgent(ctx, org.ID, "reader", human.ID, pub2); err != nil {
		t.Fatalf("distinct pubkey: %v", err)
	}
}

func TestHumanPassword(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()
	svc := identity.New(s)

	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	h, err := svc.CreateHuman(ctx, org.ID, "alice")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}

	if err := svc.SetHumanPassword(ctx, h.ID, "correct-horse-battery"); err != nil {
		t.Fatalf("SetHumanPassword: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "correct-horse-battery"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, h.ID, "wrong"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("verify wrong password err = %v, want ErrInvalidCredentials", err)
	}
	if _, err := svc.VerifyHumanPassword(ctx, "no-such-user", "x"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("verify unknown user err = %v, want ErrInvalidCredentials", err)
	}
	h2, _ := svc.CreateHuman(ctx, org.ID, "bob")
	if _, err := svc.VerifyHumanPassword(ctx, h2.ID, "anything"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("verify no-password err = %v, want ErrInvalidCredentials", err)
	}
}
