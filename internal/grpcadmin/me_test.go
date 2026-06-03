package grpcadmin

import (
	"context"
	"crypto/ed25519"
	"testing"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// incoming builds an incoming-metadata context as interchange would inject it
// after verifying the herald JWT (the server-side counterpart of the md() helper
// in grpcadmin_test.go, which builds OUTgoing metadata for the client).
func incoming(subject, org, scopes string) context.Context {
	return metadata.NewIncomingContext(context.Background(),
		metadata.Pairs("cwb-subject", subject, "cwb-org", org, "cwb-scopes", scopes))
}

func TestMe(t *testing.T) {
	id := newID(t)
	srv := &adminServer{s: New(id, fakeTokens{}, fakePurger{})}

	ctx := context.Background()
	org, err := id.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	human, err := id.CreateHuman(ctx, org.ID, "alice@x")
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := id.GrantScope(ctx, human.ID, "issue:read", human.ID); err != nil {
		t.Fatalf("GrantScope: %v", err)
	}

	// Me as the human (subject injected as interchange would).
	resp, err := srv.Me(incoming(human.ID, org.ID, ""), &heraldv1.MeRequest{})
	if err != nil {
		t.Fatalf("Me(human): %v", err)
	}
	u := resp.User
	if u.Id != human.ID || u.Kind != "human" || u.Org != org.ID || u.OrgName != "acme" || u.Status != "active" {
		t.Fatalf("human UserInfo: %+v", u)
	}
	if u.ResponsibleHuman != "" || u.Fingerprint != "" {
		t.Fatalf("human should have no agent fields: %+v", u)
	}
	hasScope := false
	for _, s := range u.Scopes {
		if s == "issue:read" {
			hasScope = true
		}
	}
	if !hasScope {
		t.Fatalf("human scopes missing issue:read: %v", u.Scopes)
	}

	// Me as an agent → agent fields populated.
	pub, _, _ := ed25519.GenerateKey(nil)
	agent, err := id.CreateAgent(ctx, org.ID, "builder", human.ID, pub)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	aresp, err := srv.Me(incoming(agent.ID, org.ID, ""), &heraldv1.MeRequest{})
	if err != nil {
		t.Fatalf("Me(agent): %v", err)
	}
	a := aresp.User
	if a.Id != agent.ID || a.Kind != "agent" || a.Org != org.ID || a.OrgName != "acme" || a.Status != "active" {
		t.Fatalf("agent UserInfo: %+v", a)
	}
	if a.ResponsibleHuman != human.ID {
		t.Fatalf("agent responsible_human = %q, want %q", a.ResponsibleHuman, human.ID)
	}
	if a.Fingerprint == "" {
		t.Fatalf("agent should have a casket fingerprint: %+v", a)
	}

	// Me with no verified subject → Unauthenticated.
	if _, err := srv.Me(ctx, &heraldv1.MeRequest{}); code(err) != codes.Unauthenticated {
		t.Fatalf("Me without cwb-subject = %v, want Unauthenticated", code(err))
	}
}
