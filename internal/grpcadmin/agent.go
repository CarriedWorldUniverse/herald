package grpcadmin

import (
	"context"

	heraldv1 "github.com/CarriedWorldUniverse/cwb-proto/gen/go/cwb/herald/v1"
	"github.com/CarriedWorldUniverse/herald/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type agentServer struct {
	heraldv1.UnimplementedAgentServiceServer
	s *Servers
}

// GetAgentByFingerprint resolves an agent from its casket fingerprint. This is
// an INTERNAL service lookup: it carries no cwb-* identity (cairn's SSH path has
// a pubkey, not a token) and is authorized by the mTLS client cert alone — so it
// is dialed directly in-cluster, never exposed on the public edge. Read-only.
func (a *agentServer) GetAgentByFingerprint(ctx context.Context, r *heraldv1.GetAgentByFingerprintRequest) (*heraldv1.GetAgentByFingerprintResponse, error) {
	if r.Fingerprint == "" {
		return nil, status.Error(codes.InvalidArgument, "fingerprint required")
	}
	agent, err := a.s.id.GetAgentByFingerprint(ctx, r.Fingerprint)
	if err != nil || agent.Kind != store.KindAgent {
		return nil, status.Error(codes.NotFound, "no agent for fingerprint")
	}
	scopes, err := a.s.id.EffectiveScopes(ctx, agent.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "scopes lookup failed")
	}
	return &heraldv1.GetAgentByFingerprintResponse{Agent: toProtoAgent(agent, scopes)}, nil
}
