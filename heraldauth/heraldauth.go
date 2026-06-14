// Package heraldauth is the consumer-side verification library for herald
// tokens. Every CWU service (nexus, cairn, ledger, porter, knowledge, comms)
// imports this to answer "who is this caller and what may they do?" from a
// herald-issued JWT — verified LOCALLY against herald's published JWKS, with
// no per-request call back to herald.
//
// Usage:
//
//	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: "https://herald.example/"})
//	id, err := v.Verify(ctx, bearerToken)
//	if id.HasScope("repo:write") { ... }
package heraldauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Identity is the verified, parsed subject of a herald token.
type Identity struct {
	Subject          string   // the principal (agent or human user id)
	Kind             string   // "agent" | "human"
	Org              string   // tenant org id
	ResponsibleHuman string   // for agents: the human who answers for it (act.sub)
	Scopes           []string // granted capabilities
	Products         []string // CWB products enabled for the org
	AgentFP          string   // casket fingerprint of the agent (if any)
	HumanFP          string   // casket fingerprint of the responsible human (if any)
}

// HasScope reports whether the identity holds the given scope.
func (id Identity) HasScope(s string) bool {
	for _, sc := range id.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// Config configures a Verifier.
type Config struct {
	// Issuer is herald's issuer URL (must match the token's `iss`).
	Issuer string
	// JWKSURL, if set, is used directly to fetch the JWKS and OIDC
	// discovery is skipped entirely. Issuer still controls the `iss`
	// claim check. Use this when the consumer can reach JWKS over a
	// different URL than the public issuer — e.g. a gateway whose
	// public Issuer is itself, so its own heraldauth must fetch
	// JWKS via the in-cluster service to avoid a boot loop.
	JWKSURL string
	// HTTPClient is used to fetch discovery + JWKS. Defaults to a 10s client.
	HTTPClient *http.Client
	// JWKSRefresh bounds how long a cached JWKS is reused before a refetch on
	// the next unknown-kid. Defaults to 1h.
	JWKSRefresh time.Duration
	// Audience, if set, is this service's own identifier; Verify then
	// requires the token's `aud` claim to include it. Leave empty to accept
	// any audience (backward compatible — pre-ID-JAG tokens carry no aud).
	Audience string
	// now is injectable for tests.
	now func() time.Time
}

// Verifier verifies herald tokens locally against a cached JWKS.
type Verifier struct {
	issuer     string
	audience   string
	jwksURI    string
	http       *http.Client
	refresh    time.Duration
	now        func() time.Time

	mu        sync.RWMutex
	keys      jose.JSONWebKeySet
	fetchedAt time.Time

	seenMu sync.Mutex
	seen   map[string]int64 // jti -> exp unix; replay guard
}

// New constructs a Verifier, fetching discovery once to locate the JWKS, then
// loading the key set. The key set is cached and refreshed lazily.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("heraldauth: issuer required")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	refresh := cfg.JWKSRefresh
	if refresh == 0 {
		refresh = time.Hour
	}
	nowFn := cfg.now
	if nowFn == nil {
		nowFn = time.Now
	}
	v := &Verifier{issuer: cfg.Issuer, audience: cfg.Audience, http: hc, refresh: refresh, now: nowFn, seen: make(map[string]int64)}

	if cfg.JWKSURL != "" {
		v.jwksURI = cfg.JWKSURL
	} else {
		jwksURI, err := v.discoverJWKS(ctx)
		if err != nil {
			return nil, err
		}
		v.jwksURI = jwksURI
	}
	if err := v.refreshKeys(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// Verify checks the token's signature against the cached JWKS and validates
// issuer + expiry, returning the parsed Identity. No network call per request
// once the JWKS is cached (only a lazy refetch on an unknown kid / stale set).
func (v *Verifier) Verify(ctx context.Context, token string) (Identity, error) {
	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return Identity{}, fmt.Errorf("heraldauth: parse: %w", err)
	}

	payload, err := v.verifyAgainstKeys(jws)
	if err != nil {
		// Unknown kid or stale set — refresh once and retry.
		if rerr := v.refreshKeys(ctx); rerr == nil {
			payload, err = v.verifyAgainstKeys(jws)
		}
		if err != nil {
			return Identity{}, fmt.Errorf("heraldauth: signature: %w", err)
		}
	}

	var c tokenClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Identity{}, fmt.Errorf("heraldauth: claims: %w", err)
	}
	if c.Issuer != v.issuer {
		return Identity{}, fmt.Errorf("heraldauth: issuer %q != %q", c.Issuer, v.issuer)
	}
	if c.Expiry == 0 || v.now().After(time.Unix(c.Expiry, 0)) {
		return Identity{}, errors.New("heraldauth: token expired")
	}
	if v.audience != "" && !audienceContains(c.Audience, v.audience) {
		return Identity{}, fmt.Errorf("heraldauth: audience %v does not include %q", c.Audience, v.audience)
	}
	if c.JTI != "" && !v.markJTI(c.JTI, c.Expiry) {
		return Identity{}, errors.New("heraldauth: token replayed (jti seen)")
	}

	id := Identity{
		Subject: c.Subject, Kind: c.Kind, Org: c.Org,
		AgentFP: c.AgentFP, HumanFP: c.HumanFP,
	}
	if c.Act != nil {
		id.ResponsibleHuman = c.Act.Subject
	}
	if c.Scope != "" {
		id.Scopes = strings.Fields(c.Scope)
	}
	id.Products = c.Products
	return id, nil
}

func (v *Verifier) verifyAgainstKeys(jws *jose.JSONWebSignature) ([]byte, error) {
	v.mu.RLock()
	keys := v.keys
	v.mu.RUnlock()
	for _, k := range keys.Keys {
		if payload, err := jws.Verify(k.Key); err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no matching key")
}

func (v *Verifier) discoverJWKS(ctx context.Context) (string, error) {
	base := strings.TrimRight(v.issuer, "/")
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := v.getJSON(ctx, base+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("heraldauth: discovery: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", errors.New("heraldauth: discovery has no jwks_uri")
	}
	return doc.JWKSURI, nil
}

func (v *Verifier) refreshKeys(ctx context.Context) error {
	var ks jose.JSONWebKeySet
	if err := v.getJSON(ctx, v.jwksURI, &ks); err != nil {
		return fmt.Errorf("heraldauth: fetch jwks: %w", err)
	}
	v.mu.Lock()
	v.keys = ks
	v.fetchedAt = v.now()
	v.mu.Unlock()
	return nil
}

func (v *Verifier) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// tokenClaims mirrors the herald access-token shape (spec §4).
type tokenClaims struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	Kind    string `json:"kind"`
	Org     string `json:"org"`
	Scope    string   `json:"scope"`
	Products []string `json:"products"`
	AgentFP  string   `json:"agent_fp"`
	HumanFP string `json:"human_fp"`
	Expiry  int64  `json:"exp"`
	Act     *struct {
		Subject string `json:"sub"`
	} `json:"act"`
	Audience any    `json:"aud"`
	JTI      string `json:"jti"`
}

// audienceContains reports whether a JWT aud claim (string or []string)
// includes want.
func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == want {
				return true
			}
		}
	}
	return false
}

// markJTI records a token's jti, returning false if it was already seen
// (replay). Expired entries are evicted on each call so the map stays bounded
// by the count of currently-live tokens.
func (v *Verifier) markJTI(jti string, exp int64) bool {
	v.seenMu.Lock()
	defer v.seenMu.Unlock()
	nowUnix := v.now().Unix()
	for j, e := range v.seen {
		if e < nowUnix {
			delete(v.seen, j)
		}
	}
	if _, dup := v.seen[jti]; dup {
		return false
	}
	v.seen[jti] = exp
	return true
}

// ProtectedResourceMetadata returns the RFC 9728 oauth-protected-resource
// document a CWB service publishes so that an agent which receives a 401 can
// discover herald as the authorization server. `resource` is the service's
// own audience identifier; `authServer` is herald's issuer URL.
func ProtectedResourceMetadata(resource, authServer string) map[string]any {
	return map[string]any{
		"resource":              resource,
		"authorization_servers": []string{authServer},
	}
}

// ProtectedResourceHandler serves ProtectedResourceMetadata as JSON. Mount it
// at /.well-known/oauth-protected-resource on the CWB service.
func ProtectedResourceHandler(resource, authServer string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata(resource, authServer))
	})
}
