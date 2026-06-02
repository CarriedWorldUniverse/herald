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
//	HERALD_REFRESH_TTL  refresh-token lifetime (Go duration, e.g. "720h"; default 30d)
//	HERALD_SIGNING_KEY  base64(std) Ed25519 private key (64 bytes). If unset, a
//	                    key is generated on boot and its public JWKS logged —
//	                    fine for dev, NOT for prod (tokens won't survive restart).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/CarriedWorldUniverse/herald/internal/adminapi"
	"github.com/CarriedWorldUniverse/herald/internal/grpcadmin"
	"github.com/CarriedWorldUniverse/herald/internal/identity"
	"github.com/CarriedWorldUniverse/herald/internal/oidc"
	"github.com/CarriedWorldUniverse/herald/internal/purge"
	"github.com/CarriedWorldUniverse/herald/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	addr := env("HERALD_ADDR", ":8099")
	dbPath := env("HERALD_DB", "/var/lib/nexus/herald.db")
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
	refreshTTL := envDuration("HERALD_REFRESH_TTL", 0) // 0 -> issuer default (30d)
	refresh := oidc.NewRefreshIssuer(provider, st, refreshTTL)
	provider.SetTokenHandler(oidc.NewGrantMux(
		oidc.NewAgentGrant(provider, idsvc, refresh),
		oidc.NewHumanGrant(provider, idsvc, refresh),
		oidc.NewRefreshGrant(provider, idsvc, refresh),
	))
	provider.SetRevokeHandler(oidc.NewRevokeHandler(refresh))

	gatewayBase := os.Getenv("HERALD_GATEWAY_URL")
	if gatewayBase == "" {
		gatewayBase = strings.TrimSuffix(strings.TrimRight(issuer, "/")+"/", "/herald/")
	}
	purger := purge.New(gatewayBase, &http.Client{Timeout: 30 * time.Second})

	api := adminapi.New(idsvc, provider)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"herald"}`))
	})
	// OIDC endpoints: discovery, JWKS, token.
	mux.Handle("/.well-known/", provider.Handler())
	mux.Handle("/jwks", provider.Handler())
	mux.Handle("/token", provider.Handler())
	// Token-authed provisioning (self-provision, validate) + the in-cluster
	// by-fingerprint lookup. The org/human/product admin surface lives in the
	// gRPC AdminService below (identity-derived authz, no static admin token).
	mux.Handle("/api/", api.Handler())

	// Genesis (Phase 4): idempotently provision the admin (administration) org +
	// platform-admin owner from a deploy secret — no shipped default account or
	// password. No-op if the admin org already exists or the secret is unset.
	if ownerID, gErr := grpcadmin.Seed(context.Background(), idsvc, grpcadmin.SeedConfig{
		AdminOrgName:     env("HERALD_GENESIS_ORG", "cwb-admin"),
		OwnerDisplayName: env("HERALD_GENESIS_OWNER", "cwadmin@carriedworld.com"),
		OwnerPassword:    os.Getenv("HERALD_GENESIS_OWNER_PASSWORD"),
	}); gErr != nil {
		log.Printf("herald: genesis skipped: %v", gErr)
	} else if ownerID != "" {
		log.Printf("herald: genesis seeded admin-org owner (login username = id %s) with %s", ownerID, grpcadmin.ScopePlatformAdmin)
	}

	// gRPC admin/internal API (Phase 4) over mTLS, fronted by interchange. OPT-IN:
	// it starts only when mTLS certs are configured (or the dev opt-in is set).
	// This is now the ONLY path to org/human/product admin (the static-admin-token
	// HTTP surface was retired in Phase 5); authz is identity-derived from the
	// herald JWT injected by interchange.
	if os.Getenv("HERALD_TLS_CERT") != "" || os.Getenv("HERALD_DEV_INSECURE") == "1" {
		grpcAddr := env("HERALD_GRPC_ADDR", ":8098")
		grpcSrv := grpc.NewServer(heraldGRPCServerOptions()...)
		grpcadmin.New(idsvc, provider, purger).Register(grpcSrv)
		healthSrv := health.NewServer()
		grpc_health_v1.RegisterHealthServer(grpcSrv, healthSrv)
		for _, svc := range []string{"cwb.herald.v1.AdminService", "cwb.herald.v1.AgentService"} {
			healthSrv.SetServingStatus(svc, grpc_health_v1.HealthCheckResponse_SERVING)
		}
		grpcLn, lErr := net.Listen("tcp", grpcAddr)
		if lErr != nil {
			log.Fatalf("herald: grpc listen %s: %v", grpcAddr, lErr)
		}
		go func() {
			log.Printf("herald grpc (admin) listening on %s", grpcAddr)
			if err := grpcSrv.Serve(grpcLn); err != nil {
				log.Fatalf("herald: grpc: %v", err)
			}
		}()
	} else {
		log.Printf("herald: gRPC admin disabled (set HERALD_TLS_* or HERALD_DEV_INSECURE=1 to enable)")
	}

	log.Printf("herald listening on %s (issuer=%s, db=%s)", addr, issuer, dbPath)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("herald: %v", err)
	}
}

// heraldGRPCServerOptions builds herald's gRPC server options. With HERALD_TLS_*
// set it enforces mTLS (RequireAndVerifyClientCert vs the cwb-ca); a partial cert
// set is fatal; HERALD_DEV_INSECURE=1 (and no certs) runs insecure for local dev.
// Mirrors the other pillars.
func heraldGRPCServerOptions() []grpc.ServerOption {
	certFile := os.Getenv("HERALD_TLS_CERT")
	keyFile := os.Getenv("HERALD_TLS_KEY")
	caFile := os.Getenv("HERALD_TLS_CA")
	if certFile == "" || keyFile == "" || caFile == "" {
		if os.Getenv("HERALD_DEV_INSECURE") == "1" {
			log.Printf("herald: HERALD_DEV_INSECURE=1 — gRPC admin WITHOUT mTLS (dev only)")
			return nil
		}
		log.Fatalf("herald: gRPC mTLS requires HERALD_TLS_CERT/_KEY/_CA (or HERALD_DEV_INSECURE=1)")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("herald: tls: load cert/key: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		log.Fatalf("herald: tls: read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		log.Fatalf("herald: tls: no certs parsed from CA file %s", caFile)
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}))}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		log.Printf("herald: ignoring invalid %s=%q", key, v)
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
