package heraldauth_test

import (
	"context"
	"net/http"

	"github.com/CarriedWorldUniverse/herald/heraldauth"
)

// ExampleVerifier shows how a CWU consumer service (cairn, ledger, porter, …)
// gates an HTTP endpoint on a herald token + a required scope. This is the
// whole integration: construct a Verifier once, then Verify per request.
func ExampleVerifier() {
	ctx := context.Background()
	v, err := heraldauth.New(ctx, heraldauth.Config{Issuer: "https://herald.example/"})
	if err != nil {
		panic(err)
	}

	// requireScope wraps a handler, enforcing a herald token with the scope.
	requireScope := func(scope string, next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tok := r.Header.Get("Authorization")
			if len(tok) > 7 && tok[:7] == "Bearer " {
				tok = tok[7:]
			}
			id, err := v.Verify(r.Context(), tok)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !id.HasScope(scope) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// id.Subject / id.Org / id.ResponsibleHuman are now trusted.
			next(w, r)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos", requireScope("repo:create", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	_ = mux
}
