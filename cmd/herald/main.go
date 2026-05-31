// Command herald is the CWU identity service: it attests who you are (humans
// and agents) and proclaims what authority you hold. Every other CWU service
// is a consumer that verifies a herald-issued JWT (see the heraldauth package).
//
// This wires the full MVP: store + identity + OIDC (EdDSA token core +
// casket jwt-bearer agent auth) + the provisioning/admin API.
//
// Config (env):
//
//	HERALD_ADDR         listen address (default :8099)
//	HERALD_DB           sqlite path (default /var/lib/nexus/herald.db; ":memory:" ok)
//	HERALD_ISSUER       OIDC issuer URL (default http://<addr>/) — set to the
//	                    externally-reachable https URL in production
//	HERALD_ADMIN_TOKEN  bearer token gating the bootstrap endpoints (required)
//	HERALD_SIGNING_KEY  base64(std) Ed25519 private key (64 bytes). If unset, a
//	                    key is generated on boot and its public JWKS logged —
//	                    fine for dev, NOT for prod (tokens won't survive restart).
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/purge"
	"github.com/CarriedWorldUniverse/herald/internal/store"
)

func main() {
	addr := env("HERALD_ADDR", ":8099")
	dbPath := env("HERALD_DB", "/var/lib/nexus/herald.db")
	adminToken := os.Getenv("HERALD_ADMIN_TOKEN")
	if adminToken == "" {
		log.Fatal("herald: HERALD_ADMIN_TOKEN is required")
	}
	issuer := env("HERALD_ISSUER", "http://"+addr+"/")

	signKey, err := loadOrGenSigningKey()
	if err != nil {
		log.Fatalf("herald: signing key: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("herald: open store %q: %v", dbPath, err)
	}
	defer st.Close()

	idsvc := identity.New(st)

	provider, err := oidc.NewProvider(oidc.Config{Issuer: issuer, SigningKey: signKey})
	if err != nil {
		log.Fatalf("herald: provider: %v", err)
	}
	provider.SetTokenHandler(oidc.NewGrantMux(
		oidc.NewAgentGrant(provider, idsvc),
		oidc.NewHumanGrant(provider, idsvc),
	))

	gatewayBase := os.Getenv("HERALD_GATEWAY_URL")
	if gatewayBase == "" {
		gatewayBase = strings.TrimSuffix(strings.TrimRight(issuer, "/")+"/", "/herald/")
	}
	purger := purge.New(gatewayBase, &http.Client{Timeout: 30 * time.Second})

	api := adminapi.New(idsvc, provider, adminToken, purger)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"herald"}`))
	})
	// OIDC endpoints: discovery, JWKS, token.
	mux.Handle("/.well-known/", provider.Handler())
	mux.Handle("/jwks", provider.Handler())
	mux.Handle("/token", provider.Handler())
	// Provisioning + admin.
	mux.Handle("/api/", api.Handler())

	log.Printf("herald listening on %s (issuer=%s, db=%s)", addr, issuer, dbPath)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("herald: %v", err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadOrGenSigningKey() (ed25519.PrivateKey, error) {
	if b64 := os.Getenv("HERALD_SIGNING_KEY"); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(raw), nil
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	log.Printf("herald: WARNING no HERALD_SIGNING_KEY set — generated an ephemeral key; tokens will not survive restart")
	log.Printf("herald: to persist, set HERALD_SIGNING_KEY=%s", base64.StdEncoding.EncodeToString(priv))
	return priv, nil
}
