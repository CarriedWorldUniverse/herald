// Package oidc is herald's token/OIDC core: an EdDSA signer, a JWKS endpoint,
// OIDC discovery, and a token endpoint. It is deliberately NOT a full
// zitadel/oidc op.Storage IdP — herald's needs are narrow (sign an access
// token, publish public keys, verify) so we use go-jose/v4 directly, which is
// far less code and fully under our control. zitadel/oidc remains available
// for richer flows if ever needed.
//
// Signing is EdDSA (Ed25519) end to end, matching the casket agent-key world.
package oidc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// defaultTokenTTL bounds issued access tokens. Short by design — the casket
// key is the durable identity; tokens are ephemeral working credentials.
const defaultTokenTTL = 10 * time.Minute

// Config configures a Provider.
type Config struct {
	// Issuer is the OIDC issuer URL (the `iss` claim + discovery base).
	Issuer string
	// SigningKey is herald's Ed25519 private key used to sign tokens.
	SigningKey ed25519.PrivateKey
	// TokenTTL overrides defaultTokenTTL when non-zero.
	TokenTTL time.Duration
	// now is injectable for tests; defaults to time.Now.
	now func() time.Time
}

// Provider signs/verifies herald tokens and serves the OIDC endpoints.
type Provider struct {
	issuer   string
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	kid      string
	ttl      time.Duration
	signer   jose.Signer
	now      func() time.Time
	tokenEP     TokenHandler // optional; set by the agent-grant task
	revokeEP    http.Handler // optional; POST /revoke
	authorizeEP http.Handler // optional; GET/POST /authorize (auth-code flow)
}

// TokenHandler handles POST /token. Wired by the agent-grant task; nil yields
// 501 so the OIDC core is usable on its own.
type TokenHandler interface {
	ServeToken(w http.ResponseWriter, r *http.Request)
}

// NewProvider builds a Provider from an Ed25519 signing key.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc: issuer required")
	}
	if len(cfg.SigningKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("oidc: signing key must be an Ed25519 private key (%d bytes), got %d", ed25519.PrivateKeySize, len(cfg.SigningKey))
	}
	pub := cfg.SigningKey.Public().(ed25519.PublicKey)
	kid := keyID(pub)
	ttl := cfg.TokenTTL
	if ttl == 0 {
		ttl = defaultTokenTTL
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: cfg.SigningKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: new signer: %w", err)
	}

	return &Provider{
		issuer: cfg.Issuer, priv: cfg.SigningKey, pub: pub, kid: kid,
		ttl: ttl, signer: signer, now: nowFn,
	}, nil
}

// SetTokenHandler wires the POST /token handler (agent-grant task).
func (p *Provider) SetTokenHandler(h TokenHandler) { p.tokenEP = h }

// SetRevokeHandler wires POST /revoke (refresh-token revocation).
func (p *Provider) SetRevokeHandler(h http.Handler) { p.revokeEP = h }

// SetAuthorizeHandler wires GET/POST /authorize (the auth-code flow task).
func (p *Provider) SetAuthorizeHandler(h http.Handler) { p.authorizeEP = h }

// Issuer returns the configured issuer URL.
func (p *Provider) Issuer() string { return p.issuer }

// TokenURL returns the canonical token endpoint URL — issuer + "/token". This
// is what the discovery doc advertises as `token_endpoint` and what agents
// MUST use as the audience claim in their jwt-bearer assertions. Comparing
// the assertion's audience against this (instead of the inbound request URL)
// lets herald sit behind a reverse proxy without breaking authentication.
func (p *Provider) TokenURL() string {
	return strings.TrimRight(p.issuer, "/") + "/token"
}

// TTL returns the access-token lifetime.
func (p *Provider) TTL() time.Duration { return p.ttl }

// Now returns the provider clock (test-injectable).
func (p *Provider) Now() time.Time { return p.now() }

// SignToken signs the given claims as a herald access token, stamping
// iss/iat/exp (caller-supplied iss/iat/exp are overwritten). Returns the
// compact JWS string.
func (p *Provider) SignToken(claims map[string]any) (string, error) {
	now := p.now()
	out := make(map[string]any, len(claims)+3)
	for k, v := range claims {
		out[k] = v
	}
	out["iss"] = p.issuer
	out["iat"] = now.Unix()
	out["exp"] = now.Add(p.ttl).Unix()

	payload, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("oidc.SignToken: marshal: %w", err)
	}
	obj, err := p.signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("oidc.SignToken: sign: %w", err)
	}
	return obj.CompactSerialize()
}

// VerifyToken verifies a herald-signed token's signature and returns its
// claims. It checks the signature, issuer, and expiry. This is the same
// verification heraldauth performs (against the public JWKS); kept here so the
// provider can self-verify and tests share one path.
func (p *Provider) VerifyToken(token string) (map[string]any, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return nil, fmt.Errorf("oidc.VerifyToken: parse: %w", err)
	}
	payload, err := jws.Verify(p.pub)
	if err != nil {
		return nil, fmt.Errorf("oidc.VerifyToken: signature: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("oidc.VerifyToken: claims: %w", err)
	}
	if iss, _ := claims["iss"].(string); iss != p.issuer {
		return nil, fmt.Errorf("oidc.VerifyToken: issuer %q != %q", iss, p.issuer)
	}
	if exp, ok := toUnix(claims["exp"]); ok && p.now().After(time.Unix(exp, 0)) {
		return nil, errors.New("oidc.VerifyToken: token expired")
	}
	return claims, nil
}

// PublicJWKS returns the public key set (no private material).
func (p *Provider) PublicJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       p.pub,
		KeyID:     p.kid,
		Algorithm: string(jose.EdDSA),
		Use:       "sig",
	}}}
}

// Handler returns the OIDC HTTP mux: discovery, JWKS, token.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.handleDiscovery)
	mux.HandleFunc("GET /jwks", p.handleJWKS)
	mux.HandleFunc("POST /token", p.handleToken)
	mux.HandleFunc("POST /revoke", p.handleRevoke)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if p.authorizeEP == nil {
			http.Error(w, "authorization endpoint not configured", http.StatusNotImplemented)
			return
		}
		p.authorizeEP.ServeHTTP(w, r)
	})
	return mux
}

func (p *Provider) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, p.PublicJWKS())
}

func (p *Provider) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimRight(p.issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                p.issuer,
		"jwks_uri":                              base + "/jwks",
		"token_endpoint":                        p.TokenURL(),
		"authorization_endpoint":                base + "/authorize",
		"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:jwt-bearer", "password", "refresh_token", "authorization_code"},
		"revocation_endpoint":                   base + "/revoke",
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"token_endpoint_auth_methods_supported": []string{"private_key_jwt", "none"}, // "none": public clients (PKCE) don't authenticate at /token
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"subject_types_supported":               []string{"public"},
	})
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	if p.tokenEP == nil {
		http.Error(w, `{"error":"token endpoint not configured"}`, http.StatusNotImplemented)
		return
	}
	p.tokenEP.ServeToken(w, r)
}

func (p *Provider) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if p.revokeEP == nil {
		http.Error(w, `{"error":"revocation not configured"}`, http.StatusNotImplemented)
		return
	}
	p.revokeEP.ServeHTTP(w, r)
}

// keyID derives a stable kid from the public key (base64url(sha256(pub)[:8])).
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}

func toUnix(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
