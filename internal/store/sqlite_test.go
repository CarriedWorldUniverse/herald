package store

import (
	"context"
	"testing"
	"time"
)

func TestRefreshToken_CreateGetRevokeChain(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	org, _ := s.CreateOrg(ctx, "acme")
	u, _ := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindHuman, DisplayName: "alice"})

	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	rt := RefreshToken{ID: "h1", ChainID: "h1", TokenHash: "hash1", UserID: u.ID, ExpiresAt: exp}
	if err := s.CreateRefreshToken(ctx, rt); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	got, err := s.GetRefreshToken(ctx, "h1")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if got.UserID != u.ID || got.ChainID != "h1" || got.TokenHash != "hash1" || got.RevokedAt != "" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.IssuedAt == "" {
		t.Fatal("IssuedAt not populated from the DB default")
	}

	// A successor in the same chain.
	if err := s.CreateRefreshToken(ctx, RefreshToken{ID: "h2", ChainID: "h1", TokenHash: "hash2", UserID: u.ID, ExpiresAt: exp}); err != nil {
		t.Fatalf("create successor: %v", err)
	}
	if err := s.RevokeRefreshChain(ctx, "h1"); err != nil {
		t.Fatalf("RevokeRefreshChain: %v", err)
	}
	for _, id := range []string{"h1", "h2"} {
		g, _ := s.GetRefreshToken(ctx, id)
		if g.RevokedAt == "" {
			t.Fatalf("token %s should be revoked after chain revoke", id)
		}
	}

	if _, err := s.GetRefreshToken(ctx, "nope"); err != ErrNotFound {
		t.Fatalf("missing token err = %v, want ErrNotFound", err)
	}
}
