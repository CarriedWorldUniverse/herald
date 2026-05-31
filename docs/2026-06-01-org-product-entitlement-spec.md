# herald: per-org product entitlement — spec

**Status:** approved design · 2026-06-01
**Goal:** herald (the core of the integrated CWB product) holds a per-org **enabled-products** registry over `{cairn, ledger, commonplace}`. An org can enable or disable each product; herald stamps the org's enabled products into every minted token, and the interchange gateway refuses a request to a disabled product's route prefix (`403`). Disabling is reversible and non-destructive — the product's data is retained, only access is blocked.
**Why now:** CWB is one integrated product with herald as the identity/org core, but nothing lets an org turn the other products on or off. This is the foundational entitlement primitive the platform needs, and the cross-pillar org-wipe (NEX-402) builds directly on it (the wipe cascades over an org's *enabled* products). Entitlement ships first; wipe is the fast-follow.

---

## 1. The one-paragraph architecture

Entitlement rides the existing identity machinery rather than introducing a new control plane. herald owns a per-org `org_product` table recording **disabled** products — a product in `{cairn, ledger, commonplace}` is **enabled unless an explicit `enabled=0` row exists** for it (a deny-list). This makes the default "everything on" (matching one integrated product) and is **migration-free**: existing orgs with no rows are fully enabled, no backfill needed. At token-mint time, both the agent (jwt-bearer) and human (password) grants add a **`products` claim** listing the org's currently-enabled products (the canonical set minus its disabled rows), exactly alongside the existing `scopes` claim. The interchange gateway — which already verifies the herald token and routes by path prefix — gains a **prefix→product map** and, after verifying the token, rejects a request whose product is not in the token's `products` claim with `403` (distinct from the `401` for no token and the `404` for an unknown route). The pillars themselves are unchanged; enforcement is a single choke point at the gateway. `heraldauth` (the gateway's verifier) exposes the new claim. Disabling is reversible (`enabled` flag flips; data untouched); a token minted before a disable carries the stale claim until it expires — the same propagation model scope changes already use.

```
  POST /api/orgs (admin)  ── creates org, default-enables all 3 products (override via "products")
        │
  POST /api/orgs/{id}/products/{p}/enable | /disable (admin) ── flips org_product.enabled
        │
  mint token (AgentGrant / HumanGrant) ── claim: products=[enabled products for org]
        │
  gateway: verify token → route by prefix → prefix's product in token.products?
        │                                         │ no
        ▼ yes                                     ▼
   proxy to pillar                              403 (product disabled for org)
```

---

## 2. Scope

**IN**
1. herald store: `org_product(org_id, product, enabled, updated_at)` + `SetProductEnabled` / `ListProducts` / `IsProductEnabled`.
2. herald identity: default-enable all products on org creation (override via create body); thin wrappers over the store methods.
3. herald oidc: a `products` claim in the minted token, in **both** `AgentGrant` and `HumanGrant`.
4. herald adminapi: `GET /api/orgs/{id}/products`, `POST /api/orgs/{id}/products/{product}/enable`, `POST /api/orgs/{id}/products/{product}/disable`; optional `products` field on `POST /api/orgs`.
5. interchange gateway: prefix→product map + `403` enforcement when the route's product is not in the token's `products` claim; `/herald` (core) always allowed.
6. heraldauth: a `Products []string` field on the verified-claims struct.

**OUT (named future work)**
- The NEX-402 cross-pillar org wipe (the fast-follow that consumes this registry).
- Org-owner **self-service** enable/disable (this spec is admin-gated, operator-managed; self-service is a later capability tied to the human web layer).
- Per-**product** scopes/quotas/billing tiers — entitlement here is a boolean on/off per product, not a plan/quota model.
- Live (per-request) entitlement lookup at the gateway — MVP relies on the token claim + natural expiry, as scopes do.
- Making `interchange`/`herald` themselves toggleable — gateway is infra, herald is core; only `{cairn, ledger, commonplace}` are products.
- Pillar-side defense-in-depth re-check of an `X-CWB-Products` header — the gateway is the single enforcement point for MVP.

---

## 3. The product set

A single canonical list, defined once in herald and referenced by the gateway's prefix map:

| product | gateway prefix | herald constant |
|---|---|---|
| `cairn` | `/cairn` | `ProductCairn` |
| `ledger` | `/ledger` | `ProductLedger` |
| `commonplace` | `/knowledge` | `ProductCommonplace` |

`herald` (`/herald`) is **core** — never in `org_product`, never gated. An unknown product name in any API → `400`. The gateway's prefix→product map is config/constant alongside the existing `INTERCHANGE_ROUTES`; a prefix with no product mapping (none today besides `/herald`) is treated as core/always-allowed.

---

## 4. Components

**`internal/store` (herald)**
- Schema: `CREATE TABLE IF NOT EXISTS org_product (org_id TEXT NOT NULL REFERENCES org(id), product TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL, PRIMARY KEY (org_id, product));`
- The table is a **deny-list**: a product is enabled unless it has an `enabled=0` row. An absent row and a present `enabled=1` row both mean "enabled". This makes the default (no rows) "all enabled" and is migration-free for existing orgs.
- `SetProductEnabled(ctx, orgID, product string, enabled bool) error` — upsert (`INSERT ... ON CONFLICT(org_id,product) DO UPDATE SET enabled=?, updated_at=?`). Idempotent.
- `IsProductEnabled(ctx, orgID, product string) (bool, error)` — single lookup; **a missing row = enabled (`true`)**; an `enabled=0` row = disabled (`false`); no error.
- `ListProducts(ctx, orgID string) (map[string]bool, error)` — the full canonical map computed as `enabled := !(row exists with enabled=0)` for each product (callers get a complete picture, not just rows present).

**`internal/identity` (herald)**
- `EnableProduct` / `DisableProduct(ctx, orgID, product string) error` — validate `product` is in the canonical set (else a typed `ErrUnknownProduct`), confirm the org exists (else `ErrNotFound`), then `store.SetProductEnabled`.
- `EnabledProducts(ctx, orgID string) ([]string, error)` — the canonical set minus its `enabled=0` rows, in canonical order (stable claim).
- On org creation (the existing `CreateOrg` path, or a thin `CreateOrgWithProducts` wrapper): default is all-enabled with **no rows written**. If an explicit subset is provided, write an `enabled=0` row for each canonical product *not* in the subset. Validate any provided names (unknown → `ErrUnknownProduct`).

**`internal/oidc` (herald)**
- In both `AgentGrant` and `HumanGrant`, after resolving the subject's org, call `identity.EnabledProducts(org)` and include `products` in the claims passed to `SignToken`. The claim is a JSON string array. (If the lookup errors, fail the mint — a token must not be issued with an unknown entitlement set.)

**`internal/adminapi` (herald)** — all admin-gated (existing `adminOnly`):
- `GET /api/orgs/{id}/products` → `{ "cairn": true, "ledger": true, "commonplace": false }` (full map, including explicitly-disabled).
- `POST /api/orgs/{id}/products/{product}/enable` and `.../disable` → `200` with the updated map; unknown `{product}` → `400`; unknown org → `404`; already in target state → idempotent `200`.
- `POST /api/orgs` gains an optional `"products": ["cairn","ledger"]` field. Absent → all enabled. Present → exactly that set enabled (the rest get an `enabled=0` row so the map is explicit); an unknown name → `400`.

**`heraldauth`**
- Add `Products []string` to the verified-claims struct; parse the `products` claim (absent/empty → empty slice).

**`interchange` (gateway)**
- A `prefixProduct` map (`/cairn`→cairn, `/ledger`→ledger, `/knowledge`→commonplace). After token verification and before proxying: resolve the request's matched route prefix to a product; if that product is non-empty and **not** in the verified claims' `Products`, return `403` (`{"error":"product not enabled for org"}`). `/herald` and any unmapped prefix → allowed. No change to prefix-strip or routing otherwise.

---

## 5. Data flow

1. **Provision:** admin `POST /api/orgs` (optionally with `products`) → org row + `org_product` rows (all enabled by default).
2. **Adjust:** admin `POST /api/orgs/{id}/products/cairn/disable` → `org_product` flips `cairn.enabled=0`.
3. **Mint:** an agent/human of that org mints a token → herald queries `EnabledProducts(org)` → token carries `products:["ledger","commonplace"]` (cairn excluded).
4. **Use:** the token hits the gateway at `/cairn/...` → gateway verifies token, maps `/cairn`→cairn, cairn ∉ `products` → `403`. A `/ledger/...` request with the same token → ledger ∈ `products` → proxied normally.
5. **Re-enable:** admin enables cairn → *new* tokens carry cairn again; existing tokens gain access when they next refresh (natural expiry).

---

## 6. Error handling

| Condition | Result |
|---|---|
| enable/disable unknown product name | `400` (`ErrUnknownProduct`) |
| enable/disable on a non-existent org | `404` |
| enable an enabled product / disable a disabled one | idempotent `200` (updated map) |
| `POST /api/orgs` with an unknown product in `products` | `400` (no org created) |
| token mint when the entitlement lookup errors | mint fails (no token issued) — never emit a token with an unknown product set |
| gateway: request to a disabled product's prefix | `403` (distinct from `401` no-token, `404` unknown route) |
| gateway: token with no `products` claim (older token / pre-rollout) | treated as **no products enabled** → `403` on any gated prefix. (Acceptable: tokens are short-lived; a fresh mint after rollout carries the claim. Noted so the rollout is understood, not a surprise.) |

---

## 7. Testing

**herald store unit:** `SetProductEnabled` upsert + idempotency; `IsProductEnabled` true/false/missing-row; `ListProducts` returns the full map.

**herald identity unit:** default-all-enabled on create; create with an explicit subset (rest explicitly disabled); `EnableProduct`/`DisableProduct` round-trip; unknown product → `ErrUnknownProduct`; missing org → `ErrNotFound`; `EnabledProducts` canonical order.

**herald oidc unit:** a minted agent token and a minted human token both carry a `products` claim equal to the org's enabled set; disabling a product and re-minting drops it from the claim.

**herald adminapi unit:** the three routes (map shape, enable/disable, unknown-product `400`, unknown-org `404`, idempotency); `POST /api/orgs` with and without `products`.

**heraldauth unit:** `products` claim parses into `Products`; absent claim → empty slice.

**interchange gateway unit:** a token whose `products` includes the route's product → proxied (existing behaviour); a token missing it → `403`; `/herald` always allowed regardless; no-`products`-claim token → `403` on a gated prefix.

**conformance (dMon):** extend the gateway layer (or a small `entitlement` layer): provision an org with cairn **disabled**, mint a token, assert a `/cairn` call through the gateway is `403` and a `/knowledge` call is `200`; enable cairn, re-mint, assert `/cairn` is now `200`. Proves the enable→claim→gateway-enforce loop end-to-end live.

**DoD:** `org_product` exists; orgs default to all products enabled (overridable on create); admin enable/disable works with the documented status codes; minted agent + human tokens carry an accurate `products` claim; the gateway returns `403` for a disabled product and proxies an enabled one with `/herald` always allowed; unit tests green across herald + heraldauth + interchange; a dMon conformance run proves the loop. The NEX-402 wipe (the consumer) is explicitly out of scope here.

---

## 8. Build sequence (for the implementation plan)

1. herald store: `org_product` schema + `SetProductEnabled`/`ListProducts`/`IsProductEnabled` + store unit tests.
2. herald identity: product constants + canonical set, `EnableProduct`/`DisableProduct`/`EnabledProducts` + `ErrUnknownProduct`, default-enable-on-create (+ explicit-subset) + identity unit tests.
3. herald oidc: `products` claim in `AgentGrant` + `HumanGrant` + oidc unit tests.
4. herald adminapi: the three product routes + `products` on create-org + adminapi unit tests.
5. heraldauth: `Products` field + claim parse + unit test.
6. interchange gateway: prefix→product map + `403` enforcement + gateway unit tests.
7. deploy: rebuild + redeploy herald and interchange on dMon; add the conformance entitlement check; run `-layers all` green.
