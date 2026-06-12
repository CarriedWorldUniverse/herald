package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// codeTTL bounds how long an authorization code is redeemable. 60s is
// generous for one redirect hop.
const codeTTL = 60 * time.Second

// PendingAuth is what an authorization code stands for: the validated
// authorize request plus the authenticated user, waiting for the token
// exchange.
type PendingAuth struct {
	ClientID      string
	RedirectURI   string
	UserID        string
	CodeChallenge string // PKCE S256 challenge, required
	expires       time.Time
}

// CodeStore holds pending authorization codes in memory. Codes are 60s,
// single-use, and herald is single-replica — losing them on restart only
// aborts in-flight logins (the user retries), so no persistence by design.
type CodeStore struct {
	mu    sync.Mutex
	codes map[string]PendingAuth
	now   func() time.Time
}

// NewCodeStore builds a CodeStore; now is injectable for tests (nil = time.Now).
func NewCodeStore(now func() time.Time) *CodeStore {
	if now == nil {
		now = time.Now
	}
	return &CodeStore{codes: map[string]PendingAuth{}, now: now}
}

// Issue mints a single-use code for the pending auth.
func (s *CodeStore) Issue(pa PendingAuth) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails on Linux/macOS/Windows; blank-discard intentional (see refresh.go)
	code := base64.RawURLEncoding.EncodeToString(b)
	now := s.now()
	pa.expires = now.Add(codeTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic sweep: the map only ever holds in-flight logins, so a
	// linear sweep on issue keeps it bounded without a background goroutine.
	for k, v := range s.codes {
		if now.After(v.expires) {
			delete(s.codes, k)
		}
	}
	s.codes[code] = pa
	return code
}

// Redeem returns and deletes the pending auth for code. Expired or unknown
// codes return ok=false.
func (s *CodeStore) Redeem(code string) (PendingAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pa, ok := s.codes[code]
	if !ok {
		return PendingAuth{}, false
	}
	delete(s.codes, code) // single-use regardless of expiry outcome
	if s.now().After(pa.expires) {
		return PendingAuth{}, false
	}
	return pa, true
}

// VerifyPKCE checks an S256 code_verifier against the stored challenge
// (RFC 7636). Empty challenges never verify — PKCE is mandatory.
func VerifyPKCE(challenge, verifier string) bool {
	if challenge == "" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
