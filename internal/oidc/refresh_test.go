package oidc

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func newRefreshStack(t *testing.T) (*RefreshIssuer, *store.SQLite, store.User) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	org, _ := st.CreateOrg(context.Background(), "acme")
	u, _ := st.CreateUser(context.Background(), store.User{OrgID: org.ID, Kind: store.KindHuman, DisplayName: "alice"})

	_, signKey, _ := ed25519.GenerateKey(nil)
	p, err := NewProvider(Config{Issuer: "http://h/", SigningKey: signKey})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return NewRefreshIssuer(p, st, 0), st, u
}

func TestRefreshIssuer_IssueValidateRotate(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)

	tok1, err := ri.Issue(ctx, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rt, err := ri.validate(ctx, tok1)
	if err != nil {
		t.Fatalf("validate fresh: %v", err)
	}
	if rt.UserID != u.ID {
		t.Fatalf("user = %q, want %q", rt.UserID, u.ID)
	}

	tok2, err := ri.rotate(ctx, rt)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := ri.validate(ctx, tok2); err != nil {
		t.Fatalf("validate rotated successor: %v", err)
	}
	// The OLD token is now revoked, and reusing it must revoke the chain so the
	// successor also dies (replay defense).
	if _, err := ri.validate(ctx, tok1); err == nil {
		t.Fatal("reused (rotated-away) token must be rejected")
	}
	if _, err := ri.validate(ctx, tok2); err == nil {
		t.Fatal("replay of the old token must revoke the whole chain (successor dead)")
	}
}

func TestRefreshIssuer_RevokeAndGarbage(t *testing.T) {
	ctx := context.Background()
	ri, _, u := newRefreshStack(t)
	tok, _ := ri.Issue(ctx, u.ID)
	ri.revoke(ctx, tok)
	if _, err := ri.validate(ctx, tok); err == nil {
		t.Fatal("revoked token must be rejected")
	}
	ri.revoke(ctx, "garbage-no-dot") // must not panic
	if _, err := ri.validate(ctx, "garbage-no-dot"); err == nil {
		t.Fatal("malformed token must be rejected")
	}
}
