package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func TestFederatedBinding_EnrollResolveAndOrgIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg acme: %v", err)
	}
	otherOrg, err := s.CreateOrg(ctx, "other")
	if err != nil {
		t.Fatalf("CreateOrg other: %v", err)
	}
	user, err := s.CreateUser(ctx, store.User{
		OrgID:       org.ID,
		Kind:        store.KindAgent,
		DisplayName: "ci",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	iss, err := s.RegisterIssuer(ctx, store.Issuer{
		OrgID: org.ID,
		Kind:  "k8s",
		Ref:   "prod-cluster",
	})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	if iss.ID == "" || iss.OrgID != org.ID || iss.Kind != "k8s" || iss.Ref != "prod-cluster" {
		t.Fatalf("bad issuer: %+v", iss)
	}

	const subject = "system:serviceaccount:build:runner"
	b, err := s.AddBinding(ctx, store.FederatedBinding{
		OrgID:    org.ID,
		UserID:   user.ID,
		IssuerID: iss.ID,
		Subject:  subject,
	})
	if err != nil {
		t.Fatalf("AddBinding: %v", err)
	}
	if b.ID == "" || b.UserID != user.ID || b.IssuerID != iss.ID || b.Subject != subject {
		t.Fatalf("bad binding: %+v", b)
	}

	gotUserID, err := s.ResolveBinding(ctx, org.ID, iss.ID, subject)
	if err != nil {
		t.Fatalf("ResolveBinding: %v", err)
	}
	if gotUserID != user.ID {
		t.Fatalf("resolved user %q, want %q", gotUserID, user.ID)
	}

	if _, err := s.ResolveBinding(ctx, otherOrg.ID, iss.ID, subject); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("same subject resolved across org boundary: %v", err)
	}
}
