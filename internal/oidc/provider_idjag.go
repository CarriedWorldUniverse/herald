package oidc

import (
	"strings"
	"time"
)

// SignShortLived signs a claim set with an explicit (typically short) TTL.
// Used for audience-scoped ID-JAGs whose lifetime is deliberately brief so a
// leaked assertion is useful only momentarily.
func (p *Provider) SignShortLived(claims map[string]any, ttl time.Duration) (string, error) {
	return p.signClaims(claims, ttl)
}

// IdentityURL returns the canonical agent-identity endpoint — issuer +
// "/agent/identity". This is what the discovery doc advertises as the
// agent_auth identity_endpoint and what agents set as the `aud` of the
// proof-of-possession assertion they present there.
func (p *Provider) IdentityURL() string {
	return strings.TrimRight(p.issuer, "/") + "/agent/identity"
}
