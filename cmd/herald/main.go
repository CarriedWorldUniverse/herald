// Command herald is the CWU identity service: it attests who you are
// (humans and agents) and proclaims what authority you hold. Every other
// CWU service is a consumer that verifies a herald-issued JWT.
//
// This is the scaffold entrypoint — healthz only. Store, identity, OIDC,
// and the admin API are wired in subsequent tasks (see
// docs/superpowers/plans/2026-05-30-herald-mvp-implementation.md).
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := os.Getenv("HERALD_ADDR")
	if addr == "" {
		addr = ":8099"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","service":"herald"}`))
	})

	log.Printf("herald listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("herald: %v", err)
	}
}
