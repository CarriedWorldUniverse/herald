package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLite_CreateOrgAndUser(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if org.ID == "" || org.Name != "acme" || org.Status != store.StatusActive {
		t.Fatalf("bad org: %+v", org)
	}

	h, err := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "jacinta"})
	if err != nil {
		t.Fatalf("CreateUser human: %v", err)
	}
	if h.ID == "" || h.Kind != store.KindHuman || h.Status != store.StatusActive {
		t.Fatalf("bad human: %+v", h)
	}

	got, err := s.GetUser(ctx, h.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.ID != h.ID || got.DisplayName != "jacinta" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestSQLite_AgentCarriesResponsibleHumanAndKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "acme")
	h, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "jacinta"})

	a, err := s.CreateUser(ctx, store.User{
		OrgID:             org.ID,
		Kind:              store.KindAgent,
		DisplayName:       "anvil",
		CasketPubkey:      []byte("0123456789abcdef0123456789abcdef"), // 32B stand-in
		CasketFingerprint: "fp-anvil",
		ResponsibleHuman:  h.ID,
	})
	if err != nil {
		t.Fatalf("CreateUser agent: %v", err)
	}
	if a.ResponsibleHuman != h.ID {
		t.Fatalf("agent must carry responsible human, got %q", a.ResponsibleHuman)
	}

	// Lookup by fingerprint (the agent-auth path uses this).
	byFp, err := s.GetUserByCasketFingerprint(ctx, "fp-anvil")
	if err != nil {
		t.Fatalf("GetUserByCasketFingerprint: %v", err)
	}
	if byFp.ID != a.ID || len(byFp.CasketPubkey) != 32 {
		t.Fatalf("fingerprint lookup wrong: %+v", byFp)
	}

	// List agents under the human (block-cascade + accountability use this).
	agents, err := s.ListAgentsByResponsibleHuman(ctx, h.ID)
	if err != nil {
		t.Fatalf("ListAgentsByResponsibleHuman: %v", err)
	}
	if len(agents) != 1 || agents[0].ID != a.ID {
		t.Fatalf("expected 1 agent under human, got %+v", agents)
	}
}

func TestSQLite_Scopes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrg(ctx, "acme")
	h, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "jacinta"})
	a, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindAgent, DisplayName: "anvil",
		CasketFingerprint: "fp", ResponsibleHuman: h.ID})

	if _, err := s.GrantScope(ctx, a.ID, "repo:write", h.ID); err != nil {
		t.Fatalf("GrantScope: %v", err)
	}
	if _, err := s.GrantScope(ctx, a.ID, "repo:read", h.ID); err != nil {
		t.Fatalf("GrantScope 2: %v", err)
	}
	// Duplicate grant is idempotent (UNIQUE(user_id, scope)).
	if _, err := s.GrantScope(ctx, a.ID, "repo:write", h.ID); err != nil {
		t.Fatalf("GrantScope dup should be idempotent: %v", err)
	}

	scopes, err := s.ListScopes(ctx, a.ID)
	if err != nil {
		t.Fatalf("ListScopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %v", scopes)
	}

	if err := s.RevokeScope(ctx, a.ID, "repo:write"); err != nil {
		t.Fatalf("RevokeScope: %v", err)
	}
	scopes, _ = s.ListScopes(ctx, a.ID)
	if len(scopes) != 1 || scopes[0] != "repo:read" {
		t.Fatalf("after revoke expected [repo:read], got %v", scopes)
	}
}

func TestSQLite_StatusAndNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrg(ctx, "acme")
	h, _ := s.CreateUser(ctx, store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "jacinta"})

	if err := s.SetUserStatus(ctx, h.ID, store.StatusBlocked); err != nil {
		t.Fatalf("SetUserStatus: %v", err)
	}
	got, _ := s.GetUser(ctx, h.ID)
	if got.Status != store.StatusBlocked {
		t.Fatalf("status not persisted: %+v", got)
	}

	if _, err := s.GetUser(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
