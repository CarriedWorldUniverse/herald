package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/store"
)

// refreshTokenGrant is the OAuth2 refresh grant type.
const refreshTokenGrant = "refresh_token"

// defaultRefreshTTL bounds a refresh token's life (overridable via NewRefreshIssuer).
const defaultRefreshTTL = 720 * time.Hour // 30 days

// RefreshStore is the persistence slice the refresh machinery needs. It is a
// subset of store.Store; the concrete SQLite store satisfies it directly.
type RefreshStore interface {
	CreateRefreshToken(ctx context.Context, rt store.RefreshToken) error
	GetRefreshToken(ctx context.Context, id string) (store.RefreshToken, error)
	RevokeRefreshChain(ctx context.Context, chainID string) error
}

// RefreshIssuer mints, validates, rotates, and revokes refresh tokens. The
// opaque token is "<id>.<secret>"; only sha256(secret) is persisted.
type RefreshIssuer struct {
	p   *Provider
	st  RefreshStore
	ttl time.Duration
}

// NewRefreshIssuer wires the issuer to a provider + store. ttl<=0 uses the default.
func NewRefreshIssuer(p *Provider, st RefreshStore, ttl time.Duration) *RefreshIssuer {
	if ttl <= 0 {
		ttl = defaultRefreshTTL
	}
	return &RefreshIssuer{p: p, st: st, ttl: ttl}
}

// Issue mints a NEW chain (chain_id == the token id) for userID and returns the
// opaque "<id>.<secret>".
func (ri *RefreshIssuer) Issue(ctx context.Context, userID string) (string, error) {
	id := randHex(16)
	return ri.persist(ctx, userID, id, id)
}

// rotate revokes the presented token's chain and issues a fresh successor in
// the same chain. Because the chain is revoked first and the successor is
// inserted after (revoked_at NULL), only the newest token is ever live.
func (ri *RefreshIssuer) rotate(ctx context.Context, old store.RefreshToken) (string, error) {
	if err := ri.st.RevokeRefreshChain(ctx, old.ChainID); err != nil {
		return "", err
	}
	return ri.persist(ctx, old.UserID, randHex(16), old.ChainID)
}

func (ri *RefreshIssuer) persist(ctx context.Context, userID, id, chainID string) (string, error) {
	secret := randB64(32)
	exp := ri.p.Now().Add(ri.ttl).UTC().Format(time.RFC3339)
	if err := ri.st.CreateRefreshToken(ctx, store.RefreshToken{
		ID: id, ChainID: chainID, TokenHash: sha256hex(secret), UserID: userID, ExpiresAt: exp,
	}); err != nil {
		return "", err
	}
	return id + "." + secret, nil
}

// validate resolves a presented refresh token to its live row, or errors.
// Reuse of a revoked (rotated) token revokes the whole chain (replay defense).
func (ri *RefreshIssuer) validate(ctx context.Context, presented string) (store.RefreshToken, error) {
	id, secret, ok := splitRefresh(presented)
	if !ok {
		return store.RefreshToken{}, errors.New("malformed refresh token")
	}
	rt, err := ri.st.GetRefreshToken(ctx, id)
	if err != nil {
		return store.RefreshToken{}, err
	}
	if subtle.ConstantTimeCompare([]byte(rt.TokenHash), []byte(sha256hex(secret))) != 1 {
		return store.RefreshToken{}, errors.New("refresh secret mismatch")
	}
	if rt.RevokedAt != "" {
		_ = ri.st.RevokeRefreshChain(ctx, rt.ChainID) // replay: kill the chain
		return store.RefreshToken{}, errors.New("refresh token revoked")
	}
	exp, err := time.Parse(time.RFC3339, rt.ExpiresAt)
	if err != nil || ri.p.Now().After(exp) {
		return store.RefreshToken{}, errors.New("refresh token expired")
	}
	return rt, nil
}

// revoke kills the chain of a presented token. Best-effort + idempotent: an
// unknown/garbage token is a silent no-op (no enumeration).
func (ri *RefreshIssuer) revoke(ctx context.Context, presented string) {
	id, _, ok := splitRefresh(presented)
	if !ok {
		return
	}
	if rt, err := ri.st.GetRefreshToken(ctx, id); err == nil {
		_ = ri.st.RevokeRefreshChain(ctx, rt.ChainID)
	}
}

// revokeChain revokes a chain by id — for callers that already hold the
// resolved row (e.g. the refresh grant revoking a blocked user's chain), so
// the store stays behind the RefreshIssuer boundary.
func (ri *RefreshIssuer) revokeChain(ctx context.Context, chainID string) error {
	return ri.st.RevokeRefreshChain(ctx, chainID)
}

func splitRefresh(s string) (id, secret string, ok bool) {
	i := strings.IndexByte(s, '.')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// crypto/rand.Read never fails on Linux/macOS/Windows; the blank-discard is intentional.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// RefreshGrant implements grant_type=refresh_token: validate the presented
// refresh token, REBUILD the access-token claims from the user record (so
// scope/product/block changes take effect), rotate the refresh token, and
// return both. Rebuilding from the record means a refreshed token can never
// carry more authority than the user currently holds.
type RefreshGrant struct {
	p       *Provider
	id      IdentityResolver
	refresh *RefreshIssuer
}

func NewRefreshGrant(p *Provider, id IdentityResolver, refresh *RefreshIssuer) *RefreshGrant {
	return &RefreshGrant{p: p, id: id, refresh: refresh}
}

func (g *RefreshGrant) ServeToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "unparseable form")
		return
	}
	presented := r.Form.Get("refresh_token")
	if presented == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "missing refresh_token")
		return
	}
	rt, err := g.refresh.validate(r.Context(), presented)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	u, err := g.id.GetUser(r.Context(), rt.UserID)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	// Enforce the block cascade at refresh time (a blocked agent/human/org can't
	// renew). IsActive evaluates the agent + its responsible human + org.
	if !g.id.IsActive(r.Context(), u.ID) {
		_ = g.refresh.revokeChain(r.Context(), rt.ChainID)
		oauthError(w, http.StatusUnauthorized, "invalid_grant", "refresh token rejected")
		return
	}
	claims, err := accessClaims(r.Context(), g.id, u)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "claims failed")
		return
	}
	access, err := g.p.SignToken(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "token signing failed")
		return
	}
	newRefresh, err := g.refresh.rotate(r.Context(), rt)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "refresh rotation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(g.p.TTL().Seconds()),
		"refresh_token": newRefresh,
	})
}
