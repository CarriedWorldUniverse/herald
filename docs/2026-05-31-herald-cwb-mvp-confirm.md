# herald — CWB MVP confirmation

**Status:** confirmation · 2026-05-31
**Goal:** record that herald's contribution to the CWB MVP — the **auth** leg of the agent loop — is **already met** by the shipped herald MVP + the deployed gateway integration, and pin the one small remaining addition + the explicit post-MVP boundary.
**Why a confirm-spec, not a build-spec:** unlike ledger/cairn/commonplace (which need building), herald's MVP surface for the CWB agent loop is shipped and proven. This doc anchors herald to the CWB MVP definition (`cwb-conformance/docs/2026-05-31-cwb-mvp-definition.md`) so the spec set is complete and the boundary is unambiguous.

---

## 1. What the CWB MVP needs from herald

The agent loop is: an aspect authenticates on its own identity, then uses git (cairn) + issues (ledger) + knowledge (commonplace). herald is the **identity authority** — the auth leg. The MVP needs:

1. **Agent auth** — an aspect mints a herald token from its casket key, non-interactively, no human in the loop.
2. **Provisioning** — agents exist in herald (seeded once, out-of-band, by the operator/admin — deployment setup, not a per-action human step).
3. **Verifiable identity at the boundary** — the gateway verifies the token and injects identity the pillars trust.

All three are **shipped**.

---

## 2. MVP surface — already met (shipped + proven this session)

- **Agent casket jwt-bearer auth** (herald MVP, NEX-376): aspect signs an RFC-7523 assertion with its casket Ed25519 key → herald issues a self-describing EdDSA JWT (`sub`=agent, `act.sub`=responsible-human, `org`, `scope`, fingerprints). Non-interactive. **Proven end-to-end through the gateway this session.**
- **Flat single org + admin-bootstrap provisioning**: the shipped admin REST seeds orgs/humans/agents out-of-band. Single-org is exactly the MVP shape (`project_cwb_mvp_definition`).
- **Gateway integration**: interchange-gateway verifies the herald token via `heraldauth` and injects `X-CWB-{Subject,Org,Kind,Scopes}`; pillars trust it over the **mTLS** gateway↔backend hop (`project_cwb_tls_everywhere`).
- **Deployed + hardened on dMon k3s**: herald + gateway live behind the auth boundary; signing key persisted; the **NEX-401 audience-from-issuer fix** (mint works behind the reverse proxy) + the **`/herald/token` public-path fix** (interchange) merged and validated in-situ; break-tests green (no-token/malformed/tampered/forged-key → 401, ClusterIP isolation).

herald's DoD for the CWB MVP — "a real aspect authenticates with its casket key → token through the gateway → a consumer verifies + enforces a scope" — is **demonstrated**.

---

## 3. The one remaining addition for the agent loop

- **NEX-412 — `GET /api/agents/by-fingerprint/{fp}`** (admin/herald): cairn's SSH ingress resolves an incoming casket pubkey → herald agent by fingerprint. The HTTP path uses the gateway's `X-CWB-*` injection (no herald change), but the **SSH path can't (SSH doesn't traverse the HTTP gateway)**, so cairn needs this lookup. Small herald story; it's herald's only net-new work for the agent-loop MVP, and it's on cairn's critical path.

That's it. Everything else herald provides for the MVP is shipped.

---

## 4. Explicitly POST-MVP (the human / commercial layer)

These are **not** required for the agent loop and are deferred (each its own spec/track):

- **path-A — human browser login** (OIDC authorization_code + sessions + email + verification + Notifier + 2FA-readiness): herald#12 + its amendment stories (NEX-393/395/396/397/398/399/400, +423/424/425). Humans-via-shadow/dashboard cover MVP oversight; per-product human logins come with the UIs.
- **org-ownership + invites + tiers** (NEX-413 + children): user-creates-org, invite links, hosted/trusted tiers, domain verification, branded invites — the commercial/multi-tenant onboarding layer. The MVP is single-org, agents admin-provisioned.
- **HS256→herald migration of nexus + ledger** (NEX-382): nexus keeps its own auth until then; the CWB surfaces are herald-authed via the gateway now.

---

## 5. DoD (already demonstrated, + the one gap)

herald meets the CWB MVP identity surface **today** — proven by the e2e mint through the gateway + the break-test battery this session. The only outstanding herald work for the full agent loop is **NEX-412** (by-fingerprint lookup) for cairn's SSH path. With that, an aspect can auth via casket over both cairn's SSH (fingerprint→agent) and the gateway HTTP path (`X-CWB-*`), and the cwb-conformance herald layer passes live.

---

## 6. Note

The cwb-conformance **herald layer (NEX-405)** is already written; it passes live once fixtures provision via the (out-of-band) admin path — which is the MVP provisioning model (single-org, admin-seeded). It does **not** require org-ownership; that earlier coupling was the commercial layer, correctly deferred (`project_cwb_mvp_definition`).
