package oidc

import (
	"context"
	"strings"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// accessClaims assembles the access-token claim set for a user FROM THE RECORD
// (never from client input). Humans get sub/kind/org/scope/products; agents
// additionally get agent_fp + act.sub (responsible human) + human_fp. This is
// the single source of truth shared by the agent, human, and refresh grants.
func accessClaims(ctx context.Context, id IdentityResolver, u store.User) (map[string]any, error) {
	scopes, err := id.EffectiveScopes(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	products, err := id.EnabledProducts(ctx, u.OrgID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"sub":      u.ID,
		"kind":     string(u.Kind),
		"org":      u.OrgID,
		"scope":    strings.Join(scopes, " "),
		"products": products,
	}
	if u.Kind == store.KindAgent {
		out["agent_fp"] = u.CasketFingerprint
		if u.ResponsibleHuman != "" {
			out["act"] = map[string]any{"sub": u.ResponsibleHuman}
			if human, err := id.GetUser(ctx, u.ResponsibleHuman); err == nil && human.CasketFingerprint != "" {
				out["human_fp"] = human.CasketFingerprint
			}
		}
	}
	return out, nil
}
