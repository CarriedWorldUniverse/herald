# herald — path-A: OIDC `authorization_code` + human login

**Status:** draft for approval · 2026-05-31
**Goal:** turn herald from "internal jwt-bearer issuer" into a real OIDC identity provider — so CWB services (cairn-native first, future reliers later) can use herald as their IdP for browser-based human login. One identity provider for humans AND agents.
**Why now:** cairn-native (NEX-384) needs human browser login. The alternative — every relier keeps its own user DB and we only use herald for agent API tokens — is two identity systems forever. Path A is the call we made (NEX-393); this spec is what we build.

This document covers the MVP cut of path-A — see §9 for the explicit DEFERRED set (refresh tokens, explicit consent UI, password reset, MFA, federation, single-logout).

---

## 1. The one-paragraph architecture

Today herald issues access tokens through a single `/token` endpoint that accepts `urn:ietf:params:oauth:grant-type:jwt-bearer` (agents, RFC 7523). Path-A adds two surfaces: a human-facing **HTML login flow** (cookie session backed by argon2id-hashed passwords), and a standard **OIDC `authorization_code` grant** (`/authorize` + extended `/token`, PKCE S256 required, redirected through the existing reverse-proxied public issuer URL). Reliers pre-register via an admin **OIDC client registry**. Access tokens minted via authz_code carry the **same shape** as agent tokens (§4) so heraldauth verifies both paths with one code path. No new claims, no new key material, no new verification primitive — just two new ways to get a token.

```
                  ┌──────────────────── herald ────────────────────────┐
   human ─ /login─►  session + HTML  ──/authorize──► authz_code        │
   relier ─/token─►  authz_code → access_token (PKCE verify)            │
   agent ─ /token─►  jwt-bearer → access_token (existing)              │
                  │                                                     │
                  │  oidc_clients · humans (+password) · sessions       │
                  │  authz_codes · JWKS · existing identity store       │
                  └─────────────────────────────────────────────────────┘
                                ▲ JWKS (public keys)
              cairn-native  · future reliers · existing CWU services
                (each verifies the JWT locally — unchanged)
```

---

## 2. MVP scope — what's IN

1. **Human credentials** — argon2id password hashes on the `humans` table; admin endpoint to set/rotate. No user-self-reset for MVP.
2. **Sessions** — cookie-backed (`herald_session`, HttpOnly + Secure + SameSite=Lax), table-stored (id, human_id, expiry, CSRF token, last_seen). 24h idle / 7d absolute timeout. Cleanup task for expired rows.
3. **Login UI** — minimal HTML: `GET /login` (form), `POST /login` (verify creds, set cookie), `POST /logout` (invalidate session). CSRF token issued on form render, validated on POST.
4. **OIDC client registry** — `oidc_clients` table (client_id, hashed client_secret, redirect_uris JSON, allowed_scopes, name, first_party bool). Admin REST: create/list/fetch/update/rotate-secret/delete. Cleartext secret returned only at create + rotate (one-time).
5. **`/authorize` endpoint** — RFC 6749 + OIDC Core 1.0. Required params: `client_id`, `redirect_uri` (exact-match), `response_type=code`, `scope` (subset of client's `allowed_scopes`), `state`, `code_challenge`, `code_challenge_method=S256`. No session → redirect to `/login?return=<encoded>`. First-party client → auto-consent; non-first-party → 400 (consent UI deferred). Issues 60-second single-use authz_code bound to client_id + redirect_uri + code_challenge + scope + human_id.
6. **`/token` authz_code grant** — extends the existing endpoint. Dispatches on `grant_type`. For `authorization_code`: validates client (basic auth or POST body, confidential clients only), looks up + atomically single-uses the code, verifies PKCE (`SHA256(verifier) == challenge`, base64url-no-pad), issues an access token with the SAME shape as agent tokens — `sub=human-id`, `kind=human`, `org`, `scope`, no `act` claim, standard exp/iat/jti.
7. **PKCE** — S256 required end-to-end (no `plain`). Public clients deferred; MVP confidential clients only.
8. **Token shape compatibility** — authz_code tokens are byte-for-byte verifiable by the existing heraldauth Verifier; no consumer changes required beyond enforcing the right scope for human callers.

---

## 3. Data model (additions to MVP)

Adds to the existing herald MVP schema (NEX-376 § 3):

```
humans
  + password_hash         text NULL    -- argon2id, encoded "argon2id$v=19$m=...,t=...,p=...$salt$hash"
  + password_updated_at   timestamp NULL

sessions
  id            text PK             -- random 32-byte base64url
  human_id      uuid FK→humans
  created_at    timestamp
  expires_at    timestamp           -- absolute (7d from creation)
  last_seen_at  timestamp           -- updated on each request; drives idle timeout
  csrf_token    text                -- random 32-byte base64url, per-session

oidc_clients
  client_id          text PK              -- human-pickable, e.g. "cairn-native-dmon"
  client_secret_hash text                 -- argon2id of generated secret
  name               text
  redirect_uris      text                 -- JSON array; exact-match only
  allowed_scopes     text                 -- JSON array
  first_party        bool                 -- auto-consent if true
  created_at         timestamp
  updated_at         timestamp

authz_codes
  code            text PK             -- random 32-byte base64url
  client_id       text FK→oidc_clients
  human_id        uuid FK→humans
  redirect_uri    text                -- bound to issuing /authorize call
  scope           text                -- space-separated, subset of client.allowed_scopes
  code_challenge  text                -- PKCE S256 challenge
  expires_at      timestamp           -- 60s from issuance
  used_at         timestamp NULL      -- set atomically on /token consumption
```

Invariants:
- One `code_challenge_method=S256` only; the column carries the challenge string verbatim.
- `used_at IS NOT NULL` is the single-use signal; the `/token` lookup is `UPDATE … WHERE used_at IS NULL RETURNING …` so two concurrent requests can't both succeed.
- `sessions.csrf_token` is generated at session creation and stays stable for the session lifetime (form re-renders read it from the row).
- Existing `humans.password_hash IS NULL` is fine and means "this human can't log in yet"; admin endpoint sets it.

---

## 4. Token shape (path-A)

Identical to the agent token (NEX-376 § 4), with the human-specific fields:

```jsonc
{
  "iss": "https://herald.<host>/herald/",     // path-A reliers see the public issuer URL
  "sub": "<human-user-uuid>",                 // the human IS the principal
  "kind": "human",
  "org": "<org-uuid>",
  "scope": "repo:read repo:write issue:read",
  "human_fp": "<casket-fp-if-the-human-has-one>",  // optional
  "exp": ..., "iat": ..., "jti": ...
}
```

No `act` claim on path-A tokens — humans aren't acting-on-behalf-of-anyone. Consumers verifying with heraldauth see `kind=human` and route accordingly. Scope vocabulary is the same as agent tokens (§7 of NEX-376 spec).

---

## 5. Auth flows (path-A)

### 5a. Browser login

1. Human visits a relier URL that requires auth (e.g. `https://cwb/cairn/<org>/<repo>`).
2. Relier responds 302 to herald's `/authorize` with `client_id`, `redirect_uri`, `response_type=code`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`.
3. `/authorize` checks the herald session cookie. None → 302 to `/login?return=<encoded /authorize URL>`.
4. Human posts credentials to `/login`. herald verifies via argon2id, creates a session row, sets `herald_session` cookie, 302 back to `/authorize`.
5. `/authorize` validates the request, looks up the client (first-party → auto-consent), generates a 60-second single-use authz_code bound to (client_id, redirect_uri, code_challenge, scope, human_id), persists it, 302 back to the relier's `redirect_uri` with `?code=...&state=...`.
6. Relier POSTs to `/token` with `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`, and `client_secret` (Basic auth header or form body).
7. `/token` authenticates the client, atomically single-uses the code, verifies PKCE, issues an access token (§4).
8. Relier holds the access token; uses it like any heraldauth-verifiable token thereafter.

### 5b. Existing agent flow (unchanged)

The jwt-bearer flow continues to work as documented in NEX-376 § 5a. Path-A adds a new branch to `/token`'s dispatch; the jwt-bearer branch is untouched.

### 5c. Provisioning humans + clients (out of band)

- An org admin creates a human via existing admin REST (NEX-376 § 7), then sets the initial password via `POST /api/humans/{id}/password` (new).
- An org admin registers an OIDC client via `POST /api/oidc/clients`; the cleartext `client_secret` is returned once at create time, never readable again. The relier stores it in its own Secret.

---

## 6. Relier integration

A first-party relier (cairn-native is the first):

1. **Register** with herald via admin REST; receive `client_id` + `client_secret` (once).
2. **Configure** the redirect URI matching what the relier serves (e.g. `https://cwb/cairn/oauth/callback`).
3. **Login route** on the relier 302s to herald `/authorize` with PKCE params and a fresh `state`.
4. **Callback route** receives `?code=...&state=...`, validates `state` against the local origination cookie, POSTs to `/token`.
5. **Token storage** — relier stores the access token in a session cookie or server-side session; verifies it on every request via heraldauth like any token.

No new code in heraldauth — the verification primitive is unchanged. The relier integration is OIDC-standard, so a generic Go OIDC client library (`golang.org/x/oauth2`, `coreos/go-oidc`) is sufficient if relier-side complexity grows.

---

## 7. API surface (additions)

New endpoints:

- `GET /login` · `POST /login` · `POST /logout` — HTML; cookie-based.
- `GET /authorize` — OIDC authz endpoint.
- `POST /token` — extends existing endpoint with `grant_type=authorization_code` branch.
- `POST /api/humans/{id}/password` — admin; sets/rotates a human's password.
- `POST /api/oidc/clients` · `GET /api/oidc/clients` · `GET /api/oidc/clients/{id}` · `PUT /api/oidc/clients/{id}` · `POST /api/oidc/clients/{id}/rotate-secret` · `DELETE /api/oidc/clients/{id}` — admin; OIDC client registry CRUD.

Updates to existing discovery doc:

- `response_types_supported` adds `code`.
- `grant_types_supported` adds `authorization_code`.
- `code_challenge_methods_supported`: `["S256"]`.
- `token_endpoint_auth_methods_supported` adds `client_secret_basic` + `client_secret_post`.

---

## 8. Deployment (path-A)

Same deployment shape as herald MVP. New environment variables:

- `HERALD_SESSION_KEY` — random 32-byte key for cookie signing (separate from the OIDC signing key). Generated if unset (warn — won't survive restart, all sessions invalidated on next boot).
- `HERALD_SESSION_TTL_IDLE` / `HERALD_SESSION_TTL_ABSOLUTE` — overrides for the defaults (24h / 7d).
- `HERALD_ARGON2_*` — tunable cost params for password hashing (memory / iterations / parallelism).

Database migration adds the new columns + tables. Migration ships with the path-A code, runs automatically on boot (same pattern as the MVP schema).

Frontend: the login UI is server-rendered HTML out of `internal/oidc/templates/`. No JS, no build step, minimal CSS. The herald binary is still a single-file scratch container.

---

## 9. Explicitly DEFERRED (NOT in path-A MVP)

- **Refresh tokens** — re-auth via session for now; defer until session lifetime becomes a friction point. Adding refresh tokens later doesn't break compatibility — heraldauth doesn't care about refresh, only access tokens.
- **Explicit consent UI** — first-party-only for MVP. The scope-grant table + consent screen come when there's a non-first-party relier.
- **Password reset / forgot-password** — admin sets initial passwords via REST; user-self-reset is later (needs email plumbing, recovery codes, etc.).
- **MFA / TOTP / passkeys** — important but deferred. Schema leaves room (additional `humans` columns can be added cleanly).
- **Public clients** — confidential only for MVP. PKCE alone provides safety, but the MVP schema requires a client_secret.
- **SSO / federation** — herald is the IdP, not a federation hub.
- **Logout-everywhere / single-logout (RP-initiated logout)** — defer until multi-relier sessions exist.
- **ID tokens / OIDC `id_token`** — MVP issues access tokens only. ID tokens add easily later (same shape, different `aud`).
- **Token introspection / revocation endpoints (RFC 7662 / 7009)** — heraldauth verifies locally; introspection isn't needed. Revocation deferred until refresh tokens exist.
- **Dynamic client registration (RFC 7591)** — admin-only registration for MVP.

---

## 10. Build sequence (for the implementation plan)

Rough order — each step independently testable:

1. **Spec + decisions sign-off** (this doc).
2. **Human credential model** — schema migration, argon2id wrapper, `VerifyHumanPassword` primitive, admin `POST /api/humans/{id}/password`. Tested in isolation. (NEX-395.)
3. **Session model + login HTML** — sessions table, cookie middleware, CSRF, `/login` + `/logout` + minimal `/account`. Tested with a real browser-style client. (NEX-396.)
4. **OIDC client registry** — schema, admin CRUD, secret hashing + one-time-return semantics. (NEX-397.)
5. **`/authorize` endpoint + PKCE** — request validation, session check + login redirect, auto-consent for first-party, authz_code persistence. (NEX-398.)
6. **`/token` authz_code grant** — dispatch on grant_type, client auth, PKCE verify, atomic single-use, token issuance with shared claim-assembly code path. (NEX-399.)
7. **E2E browser-flow integration test + cairn-client wire-up** — fake relier + browser-style HTTP client, all happy + negative cases, then wire cairn-native's `/login` against a real herald. (NEX-400.)

**Definition of done for path-A MVP:** a human opens cairn-native in a browser, lands on herald's `/login`, signs in with an admin-provisioned password, gets redirected back to cairn with an access token, and the token verifies via heraldauth and carries the human's identity + org + scopes. The full flow is exercised by an integration test.

---

## 11. Open questions for the plan (small, non-blocking)

- **Argon2id parameters** — `memory=64 MiB, iterations=3, parallelism=2` is a reasonable default for a 2026 server; pin in the spec when the plan lands. Pure-Go argon2 from `golang.org/x/crypto`.
- **CSRF mechanism** — synchroniser-token pattern (token in session, hidden form field, compared on POST). No double-submit cookie. Final-final picked in NEX-396's plan.
- **Login form templating** — Go `html/template` directly, no template-engine library. Two pages total (login + account).
- **Session ID entropy + length** — 32 random bytes base64url-no-pad → 43 chars. Same for authz_codes.
- **Discovery doc update timing** — should fold into NEX-398 (`/authorize`) so the `response_types_supported` advertised change lands with the implementation.
- **Initial cairn-native client_id** — `cairn-native-<host>` (per-deployment) or `cairn-native` (shared)? Per-deployment is safer; pin in NEX-400.
