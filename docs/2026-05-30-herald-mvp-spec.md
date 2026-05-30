# herald — MVP Spec

**Status:** draft for approval · 2026-05-30
**Goal:** the minimum identity service that lets every CWU consumer (cairn, ledger, porter, knowledge, comms, nexus) answer *"who is this caller and what may they do?"* from a verifiable token.
**Why now:** herald is the hinge — storage, knowledge, comms, and issue-tracking all need one canonical identity to gate on. Until it exists, each service invents its own auth and the cross-stack identity vision can't start.

This spec is the **MVP cut** of the full model captured in NEX-376 + memory (`project_unified_identity_ledger_hub`). The full vision (org-chart hierarchy, spend authority, cascade automation, spawned-subagent delegation, billing, SSO federation) is **explicitly deferred** — see §9. This document is what we build first.

---

## 1. The one-paragraph architecture

herald is a standalone OIDC provider written in Go on top of `zitadel/oidc` (Apache-2.0), using `casket` for crypto. It holds a small identity store (orgs, users, scopes), issues signed JWT access tokens, and publishes a JWKS endpoint. Humans authenticate by login; **agents authenticate by signing a JWT with their casket Ed25519 key** (RFC 7523 private-key-JWT / client-credentials), with no human in the loop. Every token is self-describing — it carries the subject's identity, org, responsible-human (for agents), scopes, and casket fingerprints — so consumers verify it **locally** against herald's JWKS with no per-request call back to herald. Consumers are dumb about identity internals; they trust the token.

```
                         ┌──────────── herald ────────────┐
   human ──login───────► │  zitadel/oidc  +  casket        │
   agent ──casket-JWT──► │  identity store (orgs/users/    │ ──issues──► JWT
                         │  scopes)  ·  JWKS  ·  token EP   │
                         └─────────────────────────────────┘
                                      ▲  JWKS (public keys)
            ┌─────────────────────────┼─────────────────────────┐
         nexus      cairn      ledger      porter     knowledge   comms
        (each verifies the JWT locally, reads identity+org+scope claims)
```

---

## 2. MVP scope — what's IN

1. **Orgs** — the tenant + accountability root. Flat for MVP (no manager hierarchy yet). Every user belongs to exactly one org.
2. **Users, two kinds, one type** — `human` and `agent` are the same `user` record with a `kind` discriminator. Agents carry a `responsible_human` edge (FK to a human user in the same org).
3. **Human auth** — a login flow that yields a token. MVP: password or passkey via `zitadel/oidc`'s primitives (whichever is least work; passkey preferred, password acceptable for v0).
4. **Agent auth (the make-or-break)** — agent registers a casket Ed25519 **public key**; to get a token it signs a JWT assertion with its casket **private key**; herald verifies against the registered pubkey and issues a short-lived access token. Non-interactive, no browser, no human. (RFC 7523 `urn:ietf:params:oauth:grant-type:jwt-bearer`.)
5. **Scopes / RBAC** — per-user scopes, org-bounded. MVP scopes are coarse capability strings the consumers agree on (e.g. `repo:read`, `repo:write`, `repo:create`, `issue:read`, `issue:claim`, `store:read`, `store:write`). Granted at provisioning; carried in the token. **Agent scopes are independent of the human's** (not a subset).
6. **Token issuance + JWKS** — standard OIDC: signed JWT access tokens, `/.well-known/openid-configuration`, JWKS endpoint. Consumers verify locally.
7. **Token claims** (see §4) — subject, org, responsible-human, scopes, casket fingerprints.
8. **Lifecycle / admin API** — create org; create human; create agent (register casket pubkey + scopes); grant/revoke scopes; **block a user**. Block-a-human **cascades** to that human's agents (MVP: implemented as a query — blocked-human ⇒ their agents' tokens rejected; agents may also be blocked individually).
9. **Go verification helper** — a small `heraldauth` Go package (or documented recipe) consumers drop in: fetch JWKS (cached), verify a JWT locally, return parsed `{subject, kind, org, responsible_human, scopes, fingerprints}`.

---

## 3. Data model (MVP)

```
org
  id            uuid            -- canonical org id
  name          text
  status        active|blocked
  created_at

user
  id                uuid        -- canonical identity (the "canonical UUID")
  org_id            uuid  fk→org
  kind              human|agent
  display_name      text
  status            active|blocked
  -- human auth
  login_secret      ...         -- password hash / passkey cred (human only)
  -- agent auth
  casket_pubkey     bytea       -- Ed25519 public key (agent only)
  casket_fingerprint text       -- agent only; goes in the token
  -- the accountability edge
  responsible_human uuid  fk→user  -- agent only; the human who answers for it
  created_at

scope_grant
  id            uuid
  user_id       uuid  fk→user
  scope         text            -- e.g. "repo:write"
  granted_by    uuid  fk→user   -- who granted it (accountability of the grant)
  created_at
```

Notes:
- `user.id` **is** the canonical entity UUID consumers key on.
- Flat org→users for MVP. The recursive `parent` edge (manager tree, spawned-subagent chains) is **deferred** (§9) — but the schema leaves room: `responsible_human` is already a parent-ish edge.
- `status=blocked` on a human ⇒ their agents are treated as blocked (cascade query). MVP cascade is one level (human→agents); deep trees deferred.

---

## 4. Token shape (MVP)

Signed JWT access token. Example for an **agent**:

```jsonc
{
  "iss": "https://herald.<host>/",
  "sub": "<agent-user-uuid>",          // the agent IS the principal
  "act": { "sub": "<human-user-uuid>" },// RFC 8693 actor claim: responsible human
  "org": "<org-uuid>",
  "kind": "agent",
  "scope": "repo:read repo:write repo:create issue:claim",
  "agent_fp": "<casket-fingerprint-agent>",
  "human_fp": "<casket-fingerprint-human>",   // when the human has a casket id
  "exp": ..., "iat": ..., "jti": ...
}
```

For a **human**, `sub` is the human, no `act`, `kind: "human"`.

Invariants:
- The `act`/responsible-human binding is **stamped by herald at issuance** from the agent's record — an agent **cannot** mint a token naming a different human.
- Both identity *and* the human link are **carried in the token** (not a pointer) so consumers need no lookup and accountability survives token expiry.
- Casket fingerprints make the linkage cryptographically anchored.

---

## 5. Auth flows (MVP)

### 5a. Agent token (non-interactive — the usable-AI flow)
1. Agent loads its casket private key (provisioned at agent creation).
2. Agent builds + signs a JWT assertion (`iss=sub=agent-id`, `aud=herald token endpoint`, short exp).
3. POST to herald token endpoint, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` (or client-credentials with the casket key as the client secret-equivalent).
4. herald verifies the assertion signature against the agent's registered casket pubkey, checks the agent (and its responsible human) is not blocked, and issues a short-lived access token with the §4 claims.
5. Agent uses the token until expiry; refreshes by repeating. **No browser, no human, ~a few lines of Go.**

### 5b. Human login
Standard OIDC login (passkey preferred, password acceptable for v0) → access token with `kind: human`. Consent for the agents a human owns happens **at agent-provisioning time**, not per-request.

### 5c. Provisioning (out of band)
An org admin (or the responsible human) creates an agent: registers its casket pubkey, sets `responsible_human`, grants its scopes. This is the one-time consent point.

---

## 6. Consumer integration (the payoff)

A CWU service (e.g. cairn) protects an endpoint by:
1. Fetching herald's JWKS once (cached, refreshed on rotation).
2. Verifying the incoming JWT locally: signature, `iss`, `aud`, `exp`.
3. Reading `sub`, `kind`, `org`, `act.sub`, `scope`, fingerprints.
4. Enforcing its own scope check (`repo:write` present?) + org scoping.

Shipped as a small Go package `heraldauth` so every consumer does this identically. No per-request call to herald (JWKS only). This is what "unblocks storage/knowledge/comms/tracking" concretely means: they import `heraldauth`, gate on the claims, done.

---

## 7. API surface (MVP)

OIDC standard:
- `GET /.well-known/openid-configuration`
- `GET /jwks`
- `POST /token` (jwt-bearer for agents; auth-code/password for humans)
- `GET /userinfo` (optional for MVP)

Admin (herald-admin-token gated; later: herald-issued admin scope):
- `POST /api/orgs` · `GET /api/orgs/{id}`
- `POST /api/orgs/{id}/users` (human or agent; agent body includes casket pubkey + responsible_human)
- `GET /api/users/{id}`
- `POST /api/users/{id}/scopes` · `DELETE /api/users/{id}/scopes/{scope}`
- `POST /api/users/{id}/block` · `POST /api/users/{id}/unblock` (human-block cascades to agents)

---

## 8. Deployment (MVP)

herald is **logically its own service** regardless of how it's deployed. Two modes, same binary:
- **Embedded-in-nexus (dMon hub default):** run herald in-process alongside the broker/Keel/ledger, one systemd unit. Sidesteps the bootstrap chicken-and-egg (nexus needs identity but hosts it → in-process calls need no network auth). Mirrors how ledger is embedded today.
- **Standalone (multi-tenant / public):** separate process/host; nexus authenticates to it like any other consumer. Public boundary via interchange if exposed.

MVP ships the **embedded mode** first (fastest to a working hub), with the package boundaries clean enough to split out standalone without rework. DB: Postgres (matches the zitadel/oidc + CWU direction) or SQLite for the embedded single-operator case — decide in the plan; SQLite is likely fine for MVP/dMon.

---

## 9. Explicitly DEFERRED (NOT in MVP)

These are in the full vision (NEX-376) but **out of the first cut** — listed so the MVP stays small and the boundary is unambiguous:

- **Org-chart hierarchy** beyond flat org→users — the recursive `parent` edge, manager trees, human→human reporting. (MVP: flat org; one-level human→agent cascade only.)
- **Spawned-subagent attenuated delegation** — agents spawning sub-agents with subset scopes + nested `act` chains. (MVP: agents are human-provisioned only.)
- **Spend authority axis** — delegated budget grants. (And spend *tracking* is dropped entirely under BYOAI — not ours to ledger.)
- **Billing / infra metering** — separate concern (Stripe-direct), separate service.
- **SSO / external IdP federation** (SAML/OIDC upstream, SCIM) — MVP has its own login only.
- **Automated rogue-detection → cascade** — MVP block is a manual admin action; the cascade is a query, not an automated trigger.
- **Relationship/Zanzibar authz** — MVP is coarse org-scoped RBAC scope-strings.
- **org-admin role separation + break-glass recovery** — MVP uses a static herald admin token; the separable org-admin role + solo-operator break-glass (cairn NEX-40 pattern) come after.

---

## 10. Build sequence (for the implementation plan)

Rough order — each step independently testable:
1. Repo scaffold: Go module, `zitadel/oidc` + `casket` deps, storage (Postgres/SQLite migration), config.
2. Data model + migrations + store layer (org, user, scope_grant) with tests.
3. OIDC core on `zitadel/oidc`: signing keys, JWKS, discovery, token endpoint skeleton.
4. **Agent auth (jwt-bearer + casket verification)** — the make-or-break; prove an agent can mint a token with a casket key. Test against a real casket keypair.
5. Token claim assembly (§4) — `act`, org, scopes, fingerprints; issuer-stamped human binding.
6. Human login (passkey/password).
7. Admin API (orgs/users/scopes/block) + cascade-on-human-block.
8. `heraldauth` Go consumer package + a worked example gating a dummy endpoint.
9. Embedded-in-nexus wiring (mirror ledger's embed) + dMon smoke test: a real aspect mints a herald token with its casket key and a consumer verifies it.

**Definition of done for MVP:** a real dMon aspect authenticates to herald with its casket key, receives a JWT carrying its identity + org + responsible-human + scopes, and a consumer service verifies that token locally via `heraldauth` and enforces a scope — end to end.

---

## 11. Open questions for the plan (small, non-blocking)

- SQLite vs Postgres for the embedded MVP (lean SQLite for dMon; Postgres if we want one DB story with future standalone).
- Exact agent grant: `jwt-bearer` assertion vs client-credentials-with-casket — both viable in `zitadel/oidc`; pick in step 4 by which is cleaner.
- Whether the human also always has a casket identity (affects `human_fp` presence) — MVP can leave `human_fp` optional.
- Scope string vocabulary — needs a quick cross-consumer agreement (cairn/ledger/porter/knowledge/comms each name their verbs).
