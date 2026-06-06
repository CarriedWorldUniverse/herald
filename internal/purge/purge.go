// Package purge fans an org wipe out to the CWB data pillars through the
// interchange gateway. herald mints an org:purge token and this client calls
// each pillar's self-org DELETE /api/org behind its gateway prefix. Strict:
// the first non-2xx aborts (the caller then must NOT delete herald's own org).
package purge

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// pillarPrefixes are the gateway path prefixes for the data pillars, in purge
// order. commonplace is fronted at /knowledge.
var pillarPrefixes = []struct{ name, prefix string }{
	{"cairn", "/cairn"},
	{"ledger", "/ledger"},
	{"commonplace", "/knowledge"},
}

// Client calls pillar purge routes through the gateway.
type Client struct {
	gatewayBase string
	http        *http.Client
}

// New builds a Client. gatewayBase is the interchange gateway root (no trailing
// slash needed), e.g. http://interchange-gateway.cwb.svc:8080.
func New(gatewayBase string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{gatewayBase: strings.TrimRight(gatewayBase, "/"), http: hc}
}

// PurgeOrg DELETEs each pillar's /api/org with the given purge token. Strict:
// returns an error on the first pillar that responds non-2xx, naming it. On
// full success returns a per-pillar status map.
func (c *Client) PurgeOrg(ctx context.Context, orgID, purgeToken string) (map[string]string, error) {
	res := map[string]string{}
	for _, p := range pillarPrefixes {
		url := c.gatewayBase + p.prefix + "/api/org"
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if err != nil {
			return res, fmt.Errorf("purge %s: build request: %w", p.name, err)
		}
		req.Header.Set("Authorization", "Bearer "+purgeToken)
		resp, err := c.http.Do(req)
		if err != nil {
			return res, fmt.Errorf("purge %s: %w", p.name, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return res, fmt.Errorf("purge %s: status %d", p.name, resp.StatusCode)
		}
		res[p.name] = "ok"
	}
	return res, nil
}
