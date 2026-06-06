package purge_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/CarriedWorldUniverse/herald/internal/purge"
)

func TestPurgeOrg_AllSucceed(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer TOK" {
			t.Errorf("auth = %q", got)
		}
		seen = append(seen, r.URL.Path)
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	c := purge.New(srv.URL, srv.Client())
	res, err := c.PurgeOrg(context.Background(), "org1", "TOK")
	if err != nil {
		t.Fatalf("PurgeOrg: %v", err)
	}
	for _, p := range []string{"cairn", "ledger", "commonplace"} {
		if res[p] != "ok" {
			t.Fatalf("result[%s] = %q, want ok (res=%+v)", p, res[p], res)
		}
	}
	want := []string{"/cairn/api/org", "/ledger/api/org", "/knowledge/api/org"}
	for _, wp := range want {
		found := false
		for _, s := range seen {
			if s == wp {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a DELETE to %s; saw %v", wp, seen)
		}
	}
}

func TestPurgeOrg_StrictAbortsOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ledger") {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	c := purge.New(srv.URL, srv.Client())
	_, err := c.PurgeOrg(context.Background(), "org1", "TOK")
	if err == nil || !strings.Contains(err.Error(), "ledger") {
		t.Fatalf("expected strict error naming ledger, got %v", err)
	}
}
