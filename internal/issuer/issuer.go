package issuer

import (
	"context"
	"sync"
)

// IssuerVerifier verifies an external attestation and returns the external
// subject to resolve against herald's enrolled federated bindings.
type IssuerVerifier interface {
	Verify(ctx context.Context, attestation string) (subject string, err error)
}

// Registry maps enrolled issuer IDs to their verifier.
type Registry struct {
	mu       sync.RWMutex
	verifier map[string]IssuerVerifier
}

func NewRegistry() *Registry {
	return &Registry{verifier: make(map[string]IssuerVerifier)}
}

func (r *Registry) Register(issuerID string, v IssuerVerifier) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.verifier[issuerID] = v
}

func (r *Registry) Verifier(issuerID string) (IssuerVerifier, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.verifier[issuerID]
	return v, ok
}
