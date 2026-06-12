package oidc

import (
	"fmt"
	"net/url"
	"strings"
)

// Client is one registered OAuth2 client. All herald clients are PUBLIC
// (browser apps): PKCE is the proof-of-possession, there is no client secret.
type Client struct {
	ID          string
	RedirectURI string
}

// ClientRegistry holds the statically-registered OAuth2 clients. Clients are
// deployment config (HERALD_OIDC_CLIENTS), not runtime data — registering a
// client IS a deploy, which matches the platform's declarations-are-truth
// posture.
type ClientRegistry struct {
	clients map[string]Client
}

// ParseClients parses "id|redirectURI[,id|redirectURI...]" into a registry.
// Redirect URIs must be https, except localhost (dev). Empty input is a valid
// empty registry (the authorize endpoint then rejects everything).
func ParseClients(s string) (*ClientRegistry, error) {
	r := &ClientRegistry{clients: map[string]Client{}}
	if strings.TrimSpace(s) == "" {
		return r, nil
	}
	for _, entry := range strings.Split(s, ",") {
		id, redirect, ok := strings.Cut(strings.TrimSpace(entry), "|")
		if !ok || id == "" || redirect == "" {
			return nil, fmt.Errorf("oidc: malformed client entry %q (want id|redirectURI)", entry)
		}
		u, err := url.Parse(redirect)
		if err != nil {
			return nil, fmt.Errorf("oidc: client %s: bad redirect %q: %w", id, redirect, err)
		}
		if u.Scheme != "https" && u.Hostname() != "localhost" {
			return nil, fmt.Errorf("oidc: client %s: redirect must be https (or localhost for dev), got %q", id, redirect)
		}
		r.clients[id] = Client{ID: id, RedirectURI: redirect}
	}
	return r, nil
}

// Lookup returns the client by id.
func (r *ClientRegistry) Lookup(id string) (Client, bool) {
	c, ok := r.clients[id]
	return c, ok
}

// ValidateRedirect requires an EXACT redirect-URI match (no prefix logic —
// exact match is the only safe comparison for redirect URIs).
func (r *ClientRegistry) ValidateRedirect(clientID, redirect string) error {
	c, ok := r.clients[clientID]
	if !ok {
		return fmt.Errorf("oidc: unknown client %q", clientID)
	}
	if c.RedirectURI != redirect {
		return fmt.Errorf("oidc: redirect %q not registered for client %q", redirect, clientID)
	}
	return nil
}
