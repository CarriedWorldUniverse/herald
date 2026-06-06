# herald path-A human login (password v0) — spec

**Status:** approved design · 2026-06-01
**Goal:** let a human authenticate with a real credential and receive a `kind:human` access token, replacing the admin-token stand-in (`POST /api/humans/{id}/token`). This makes a human's identity genuinely authenticated rather than minted-by-admin, and lets the conformance journey's reviewer be a real human.
**Why now:** path-A login is the last piece keeping the cross-service journey's human-review step a stand-in. herald's MVP spec (§5b/§5a) already blesses a **password** login for v0 ("passkey preferred, password acceptable for v0"), the store schema already carries an unused `login_secret` column, and the plumbing (single `/token` handler, `identity.CreateHuman`, `x/crypto/bcrypt`) is in place. This implements that deferred v0.

This is **path-A login only**. The full "human browser review" also wants a cairn web UI to render a diff; that is a separate, deferred deliverable (and not something a headless conformance test exercises). Building login makes the human *identity* real; the browser-rendered review surface is future.

---

## 1. The one-paragraph architecture

A human's password is set by an admin (`POST /api/humans/{id}/password`), bcrypt-hashed into the existing `login_secret` column. The human then logs in with the OAuth2 **password grant** at the existing `/token` endpoint (`grant_type=password`, `username` = the human's user id, `password`), and herald returns a self-describing `kind:human` access token (sub, org, scopes) signed by the same key/JWKS as agent tokens — so every consumer (gateway, ledger, cairn) verifies and trusts it identically, with no consumer change. The `/token` endpoint becomes a small **grant dispatcher**: `jwt-bearer` → the existing agent grant, `password` → the new human grant. Because a logged-in human needs scopes to do anything, human creation gains an optional `scopes` list (mirroring agent creation). Every login failure returns a uniform `401 invalid_grant` (no user enumeration).

```
  admin ─ POST /api/humans/{id}/password {password} ─► bcrypt → login_secret
  human ─ POST /token grant_type=password
                username=<user id> password=…            ─► verify bcrypt + active
                                                              → SignToken{sub,kind:human,org,scope}
                                                              → kind:human access token
  /token dispatch:  grant_type=jwt-bearer → AgentGrant (unchanged)
                    grant_type=password   → HumanGrant   (new)
                    else                  → unsupported_grant_type
```

---

## 2. Scope

**IN**
1. `POST /api/humans/{id}/password {password}` (admin) — set/replace a human's bcrypt password hash in `login_secret`.
2. Optional `scopes []string` on `POST /api/orgs/{org}/humans` — grant scopes at human creation (mirrors agents), so a logged-in human can act.
3. Password grant at `/token` (a grant dispatcher + a new `HumanGrant`) issuing a `kind:human` token.
4. Conformance close-the-loop: fixtures provision humans with a real password + log in via the grant (retiring the admin stand-in on the human path); the journey's reviewer becomes a real human (alice); a herald conformance-layer assertion for human login.

**OUT (named future work)**
- Passkey / WebAuthn (the spec's preferred end state).
- Auth-code + server-rendered login page (browser redirect flow).
- Email / login-name as username (MVP: username = the human's user id).
- Password reset/rotation policy, account lockout, login rate-limiting.
- cairn web UI for visual diff review.
- SSO / external IdP federation.

---

## 3. API

### `POST /api/humans/{id}/password`  (admin-gated)
Body: `{ "password": "…" }`. Validates: the user exists and is a human (else `400`/`404`); password length ≥ 8 (else `400`). bcrypt-hashes (default cost) and stores in `login_secret`. Returns `200 {}`. Idempotent (replaces any existing hash).

### `POST /api/orgs/{org}/humans`  (admin-gated, extended)
Body gains optional `scopes []string`:
```json
{ "display_name": "alice", "scopes": ["issue:read", "issue:write"] }
```
Creates the human (as today) then grants each scope via `identity.GrantScope`. Omitting `scopes` behaves exactly as before.

### `POST /token`  (public, extended)
Now dispatches on `grant_type`:
- `urn:ietf:params:oauth:grant-type:jwt-bearer` → existing `AgentGrant` (unchanged).
- `password` → new `HumanGrant`. Form params: `username` (= the human's user id), `password`.
  - Looks up the user. **Uniform `401 invalid_grant`** if: not found, not a human, inactive (block cascade via `identity.IsActive`), `login_secret` unset, or bcrypt mismatch. No response detail distinguishes these (no enumeration).
  - On success: claims `{ sub: <id>, kind: "human", org: <orgID>, scope: <space-joined effective scopes> }`, signed via `provider.SignToken`. No `agent_fp`/`act`.
  - Response: standard OAuth token JSON (`{access_token, token_type:"Bearer", ...}`), same shape as the agent grant.
- any other `grant_type` → `400 unsupported_grant_type`.

---

## 4. Components

- **`internal/store`**: a method to update a user's `login_secret` (e.g. `SetLoginSecret(ctx, userID, hash string) error`). The column already exists.
- **`internal/identity`** owns BOTH sides of the credential so the bcrypt choice lives in one place: `SetHumanPassword(ctx, userID, plaintext string) error` (verify the user is a human, bcrypt-hash, store) and `VerifyHumanPassword(ctx, userID, plaintext string) (store.User, error)` (load the user, confirm human + active, `bcrypt.CompareHashAndPassword`, returning a uniform error on any failure). The HTTP/grant layer never touches bcrypt directly.
- **`internal/oidc`**: a `tokenDispatcher` (implements the provider's `TokenHandler`) that routes by `grant_type` to the agent grant or the new `HumanGrant`; `HumanGrant` (mirrors `AgentGrant`'s shape — deps: identity service + provider). `SetTokenHandler` is given the dispatcher instead of the bare agent grant.
- **`internal/adminapi`**: `handlePasswordSet` + route; `handleCreateHuman` extended to accept + grant `scopes`. The `Identity` interface there gains what it needs (`SetHumanPassword`; `GrantScope` already present).
- **`cmd/herald`**: wire the dispatcher (compose agent grant + human grant) into `SetTokenHandler`.

---

## 5. Token + consumer behaviour

A human token is a normal herald JWT, signed by the same key, verifiable against the same JWKS. Claims: `sub`, `kind:"human"`, `org`, `scope`. The gateway injects `X-CWB-Subject`=human id, `X-CWB-Org`, `X-CWB-Kind`=`human`, `X-CWB-Scopes`. ledger/cairn already authorize purely on subject/org/scopes (kind-agnostic), so **no consumer code changes** — a human with `issue:write` can comment/transition a ledger issue exactly as an agent with that scope can.

---

## 6. Conformance close-the-loop

- **`fixtures.ProvisionOrg`**: for each fixture human, create it (alice with `scopes:["issue:read","issue:write"]`), set a password (admin), then obtain its token via the **password grant** (a new `wire`/fixtures helper `LoginHuman(tokenURL, userID, password)`), storing it on the `Principal`. This replaces the admin stand-in (`/api/humans/{id}/token`) for humans; the stand-in remains for bootstrap but fixtures no longer use it.
- **`conformance/herald`**: add a subtest that sets a password and logs in via the password grant, asserting the token decodes to `kind:"human"` with the right `sub`/`org`/`scope`, and that a wrong password → `401`.
- **`conformance/journey`**: in the ledger setup, register alice as a ledger user with `kind:"human"` (ledger's user kinds are `human`|`ai`) + org member; the review step (the comment + In Review → Done transitions) uses **alice's real human-login token** instead of the admin agent.

---

## 7. Error handling

| Condition | Result |
|---|---|
| set-password: unknown user / not a human | 404 / 400 |
| set-password: password too short | 400 |
| login: unknown user / not a human / inactive / no password set / wrong password | **401 `invalid_grant`** (uniform) |
| login: missing username or password | 400 `invalid_request` |
| `/token` unknown grant_type | 400 `unsupported_grant_type` |
| login success | 200 + `kind:human` access token |

---

## 8. Testing

**herald unit:**
- set-password stores a bcrypt hash that verifies; rejects short passwords + non-human ids.
- password grant: correct password → token decodes to `{kind:"human", sub, org, scope}`; wrong password → 401; non-human (agent) user id → 401; blocked human (or blocked org) → 401; human with no password set → 401.
- the dispatcher still serves `grant_type=jwt-bearer` for agents unchanged (agent golden path still passes); unknown grant → `unsupported_grant_type`.
- human created with `scopes` has those effective scopes; without `scopes`, none (unchanged).

**conformance:** fixtures real human-login green across all layers; `conformance/herald` human-login assertion; `conformance/journey` reviewer = alice (real human token) and the journey passes end to end.

**DoD:** an admin sets a human's password; the human logs in at `/token` with the password grant and receives a `kind:human` token carrying their org + scopes; a wrong password is rejected `401 invalid_grant`; agent jwt-bearer login is unchanged; the conformance fixtures provision humans by real login and the journey's review is performed by a real human identity; deployed to dMon and the conformance suite is green.

---

## 9. Build sequence (for the implementation plan)

1. store `SetLoginSecret` + identity `SetHumanPassword`/password verify (bcrypt) + unit tests.
2. `HumanGrant` + the `/token` grant dispatcher + provider wiring + unit tests (incl. agent grant still works).
3. adminapi: `POST /api/humans/{id}/password` + `scopes` on human-create + unit tests; `cmd/herald` dispatcher wiring.
4. Deploy herald to dMon; flip the conformance fixtures + journey + add the herald-layer human-login assertion; run the suite green.
