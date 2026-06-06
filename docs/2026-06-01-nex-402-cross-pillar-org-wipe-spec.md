# NEX-402: cross-pillar org wipe — spec

**Status:** approved design · 2026-06-01
**Ticket:** NEX-402 (Bug → capability). Consumes [[NEX-427]] (per-org product entitlement, shipped).
**Goal:** Deleting an org removes **all** of its data across every CWB pillar — herald identity, cairn repos, ledger issues/projects, commonplace knowledge — via a single herald-orchestrated, admin-gated operation. This makes conformance teardown a real wipe (and `cwb-conform -reap` a real sweep), replacing the current "block the test humans / leave the org as an orphan" placeholder.
**Why now:** every conformance + CI run orphans a `cwb-test-*` org (no delete path exists), accruing dead identities + repos + issues + knowledge on dMon. The entitlement work (NEX-427) put the last prerequisite in place: herald can mint a scoped token and the gateway enforces it, so an org-bound purge through the gateway is now possible.

---

## 1. The one-paragraph architecture

herald is the org's system-of-record, so org deletion is herald-rooted. `DELETE /api/orgs/{id}` (admin-token gated, **confirm-by-name**) mints a short-lived **purge token** herald self-signs — `{sub:"system:purge", kind:"agent", org:id, scope:"org:purge", products:[all canonical], exp:~30s}` — and calls each data pillar **through the interchange gateway** (`<gateway>/cairn/api/org`, `/ledger/api/org`, `/knowledge/api/org`, all `DELETE`). The gateway verifies the token and injects `X-CWB-Org=id` + `X-CWB-Scopes=org:purge`; each pillar's **self-org purge** route (gated by the new `org:purge` scope) deletes its data **WHERE org == X-CWB-Org** — never a foreign org in a path, honoring the platform's tenancy rule. The purge token carries **all** products so the gateway's entitlement gate does not 403 a disabled product (a wipe must purge retained data of disabled products too). The operation is **strict / all-or-nothing at the existence boundary**: herald deletes its own identity rows (`scope_grant → org_product → user → org`) **only after every pillar purge returns 2xx**; the first pillar failure aborts with an error and leaves the herald org intact. Pillar purges are **idempotent no-ops** when the org has no data there, so a retry — or an org that never used a pillar — wipes cleanly. The conformance reaper talks **only** to herald: list orgs → filter `cwb-test-*` → `DELETE` each; herald fans out the rest.

```
  DELETE /api/orgs/{id}  {name:"<org name>"}      (herald, admin token + confirm-by-name)
        │  name matches stored org? ──no──► 409
        ▼ yes — mint purge token {org:id, scope:org:purge, products:[all]}
   for pillar in [cairn, ledger, commonplace]:
        herald → <gateway>/<prefix>/api/org  DELETE  (Bearer purgeToken)
              gateway verifies token, injects X-CWB-Org=id, X-CWB-Scopes=org:purge
              pillar purges WHERE org == X-CWB-Org (idempotent; no data → 200 no-op)
        │ any non-2xx ──► ABORT: 502, herald org NOT deleted (retryable)
        ▼ all 2xx
   herald Store.DeleteOrg(id)   scope_grant → org_product → user → org   (LAST)
        ▼
   200 {deleted: id, pillars: {cairn:ok, ledger:ok, commonplace:ok}}
```

---

## 2. Scope

**IN**
1. herald `Store.DeleteOrg(ctx, orgID)` — cascade delete of `scope_grant` (by the org's users), `org_product`, `user`, then `org`, in one transaction.
2. herald `GET /api/orgs` (admin) — list orgs (`id`, `name`, `status`) for the reaper to discover orphans.
3. herald `DELETE /api/orgs/{id}` (admin) — confirm-by-name, mint the purge token, orchestrate the gateway fan-out (strict), then `DeleteOrg` last.
4. herald `internal/purge` — the small HTTP client that calls the three pillar purge routes through the gateway; the gateway base is derived from `HERALD_ISSUER`.
5. The `org:purge` scope constant; herald mints it **only** into the ephemeral purge token (never grantable to a normal agent).
6. **cairn / commonplace**: a self-org purge route `DELETE /api/org` gated by `org:purge`, deleting WHERE `org == X-CWB-Org` (idempotent). cairn also removes the on-disk bare repos.
7. **ledger**: a self-org purge route `DELETE /api/org` gated by `org:purge` → `DeleteOrganisation(X-CWB-Org)` (reuses its FK cascade; idempotent).
8. **cwb-conformance**: `Teardown` and `-reap` rewired to herald `GET /api/orgs` + `DELETE /api/orgs/{id}`; a conformance **reap layer** proving the cascade live.

**OUT (named future work)**
- 2-phase-commit / cross-service transactional rollback — we get effective atomicity via "herald identity deleted last + idempotent retryable pillar purges", not a distributed transaction.
- Soft-delete / undo / tombstones — a wipe is a hard delete.
- Deleting individual users/repos/issues by id from this endpoint — org-granularity only here.
- A general operator UI / CLI for wiping arbitrary (non-test) orgs — the endpoint supports it (admin + confirm-by-name), but the only automated caller is the test reaper (prefix-guarded).
- Per-product selective wipe — this deletes the whole org across all pillars.

---

## 3. The `org:purge` scope + purge token

A new scope string `org:purge`. It is **never** added to any agent's `scope_grant` rows and is **not** in any pillar's normal scope vocabulary except its purge route. herald mints it into a self-signed token via `provider.SignToken`:

```
{ "sub":"system:purge", "kind":"agent", "org":"<id>",
  "scope":"org:purge", "products":["cairn","ledger","commonplace"], "exp":<now+30s> }
```
- `products:[all canonical]` so the gateway's entitlement gate (NEX-427) passes for every pillar, including ones the org has disabled (whose retained data must still be purged).
- `sub:"system:purge"` is synthetic — it need not exist in herald's `user` table; the gateway's `heraldauth` verifies only the signature + `iss` + `exp` and reads claims, and pillars purge **by org**, not by subject.
- Short TTL (~30s) bounds the blast radius of the token.

The gateway requires no change: it verifies the token, injects `X-CWB-Org`/`X-CWB-Scopes`/`X-CWB-Products`, applies its existing entitlement check (passes — all products present), and proxies.

---

## 4. Components

**herald `internal/store`**
- `DeleteOrg(ctx, orgID string) error` — in ONE transaction, with FK checks deferred to commit so intra-org self-references (the `user.responsible_human → user(id)` and `scope_grant.granted_by → user(id)` FKs) don't fail mid-statement during the bulk deletes:
  1. `PRAGMA defer_foreign_keys = ON;` (first statement in the Tx; connection-scoped, resets after the Tx — a no-op when `foreign_keys` is off, e.g. `:memory:` tests)
  2. `DELETE FROM scope_grant WHERE user_id IN (SELECT id FROM user WHERE org_id=?) OR granted_by IN (SELECT id FROM user WHERE org_id=?);` (clears grants both *to* and *by* the org's users — removes any inbound FK reference)
  3. `DELETE FROM org_product WHERE org_id=?;`
  4. `DELETE FROM user WHERE org_id=?;`
  5. `DELETE FROM org WHERE id=?;`
  6. `COMMIT` — FKs are validated here, by which point every org row and its references are gone, so the graph is consistent.
  Idempotent (deleting an absent org affects 0 rows, no error). Use a `database/sql` `Tx` so all statements run on one connection (required for the per-connection `defer_foreign_keys` pragma). Add to the `Store` interface.

**herald `internal/identity`**
- `DeleteOrg(ctx, orgID)` passthrough to the store (keeps adminapi talking to the identity service, consistent with the rest).
- `ScopeOrgPurge = "org:purge"` constant (exported for the oidc minting + documented as ephemeral-only).

**herald `internal/oidc` (or a small mint helper)**
- A `MintPurgeToken(orgID string) (string, error)` on the provider/grant surface that builds the claims in §3 and calls `SignToken`. (No new grant endpoint — herald mints it internally during the DELETE handler.)

**herald `internal/purge`** (new package)
- `Client` with the gateway base URL + an `http.Client`. `PurgeOrg(ctx, orgID, purgeToken string) (map[string]string, error)` calls `DELETE <gateway>/<prefix>/api/org` for `cairn`,`ledger`,`knowledge` (the gateway prefixes, mirroring the entitlement `RouteProducts` map) with `Authorization: Bearer <purgeToken>`. **Strict:** returns an error on the first pillar that responds non-2xx (naming it); returns the per-pillar `ok` map on full success. The gateway base is `strings.TrimSuffix(issuer, "/herald/")` (or derived from the configured issuer); injected via config, not hard-coded.

**herald `internal/adminapi`**
- `GET /api/orgs` (admin) → `[{id,name,status}]` (add `ListOrgs` to the store + identity surface).
- `DELETE /api/orgs/{id}` (admin): decode `{name}`; `GetOrg(id)` (404 if absent); if `body.name != org.Name` → `409` ("org name confirmation does not match"); mint the purge token; `purge.Client.PurgeOrg(id, token)` — on error → `502` with the failing pillar, **herald org untouched**; on success → `identity.DeleteOrg(id)` → `200 {deleted:id, pillars:{...}}`.
- The handler needs the gateway base URL + the provider (to mint) wired in `cmd/herald/main.go` (derive gateway base from `HERALD_ISSUER`; allow an explicit `HERALD_GATEWAY_URL` override).

**cairn** (`internal/httpd`)
- Register `DELETE /api/org` → a handler gated on `org:purge` (read from the injected `X-CWB-Scopes`). It lists repos WHERE `org_id == X-CWB-Org` and `DeleteRepo` each (existing method: row + on-disk + PR/push cascade). Idempotent: zero repos → `200`. Returns `200 {purged:"<org>", repos:<n>}`.

**commonplace**
- Register `DELETE /api/org` → gated on `org:purge` → `DELETE FROM entry WHERE org == X-CWB-Org` (fts/vec cascade). Idempotent: zero rows → `200`. Returns `200 {purged:"<org>", entries:<n>}`.

**ledger**
- Register `DELETE /api/org` (gateway-mode, gated on `org:purge` via `X-CWB-Scopes`) → `DeleteOrganisation(X-CWB-Org)` (projects/issues/etc. cascade via existing FKs). Idempotent: absent organisation → `200` no-op. Returns `200 {purged:"<org>"}`. (Distinct from the existing slug-in-path `DELETE /api/admin/orgs/{slug}`, which stays; this self-org route is the one the wipe uses, honoring the org-bound rule.)

**cwb-conformance**
- `internal/fixtures.Teardown`: replace the per-human `block` attempt with a single `DELETE <HeraldAdminBase>/api/orgs/{id}` carrying `{"name": org.Name}` (admin token). Best-effort + logged (teardown must never fail a run), but now it actually wipes.
- `cmd/cwb-conform -reap`: `GET <HeraldAdminBase>/api/orgs` → filter names with prefix `cwb-test-` → `DELETE` each with its name. Log a count.
- A new **reap conformance layer**: provision an org, write data in all pillars (a repo, an issue, a knowledge entry), `DELETE` it via herald, then assert each pillar no longer has it (cairn repo gone, ledger issue 404, commonplace entry gone) and herald `GET /api/orgs` no longer lists it.

---

## 5. Data flow (happy path + abort)

1. Reaper (or operator) `GET /api/orgs` → finds `cwb-test-<run>` (id `X`, name `N`).
2. `DELETE /api/orgs/X` body `{"name":"N"}` with the admin token.
3. herald: `GetOrg(X)` → name matches `N` ✓. Mint purge token `T` `{org:X, scope:org:purge, products:[all]}`.
4. herald → `DELETE <gateway>/cairn/api/org` (Bearer T) → gateway injects `X-CWB-Org=X` → cairn deletes its repos for X → `200`. Same for `/ledger/api/org`, `/knowledge/api/org`.
5. All `200` → herald `DeleteOrg(X)` (txn: grants→org_product→users→org) → `200 {deleted:X, pillars:{cairn:ok,ledger:ok,commonplace:ok}}`.
6. **Abort variant:** if step 4 hits a non-2xx (say ledger `500`), herald returns `502 {error, failed:"ledger"}` and **does not** call `DeleteOrg`. Org X still exists in herald; cairn may already be purged (idempotent). A retry re-runs all pillar purges (cairn = no-op) + ledger, then deletes herald. Safe.

---

## 6. Error handling

| Condition | Result |
|---|---|
| `DELETE` without admin token | `401`/`403` (existing `adminOnly`) |
| org id not found | `404` |
| `name` missing or ≠ stored org name | `409` (confirmation mismatch; nothing deleted) |
| any pillar purge non-2xx | `502` naming the failed pillar; herald org NOT deleted; retryable |
| all pillars 2xx, `DeleteOrg` fails | `500`; pillars already purged but herald org remains → retry (pillar purges no-op, herald delete retried) |
| pillar purge of an org with no data there | `200` no-op (idempotent — required for strict mode + orgs that never used a pillar) |
| purge route hit without `org:purge` scope (e.g. a normal agent token) | `403` at the pillar (scope check) |
| purge route reached without the gateway (no `X-CWB-Org`) | `400`/`401` at the pillar (no org context) — defense in depth |

---

## 7. Testing

**herald store unit:** `DeleteOrg` removes the org + its users + their scope_grants + its org_product rows in one txn; deleting an absent org is a no-op (no error); an unrelated org is untouched.

**herald purge client unit:** with a stub gateway/pillar HTTP server — all-2xx returns the ok map; a non-2xx aborts with the failing pillar named (strict); the `Authorization: Bearer` header carries the purge token.

**herald adminapi unit:** `GET /api/orgs` lists; `DELETE` with mismatched/missing name → `409` and no deletion (stub the purge client); `DELETE` happy path calls purge then `DeleteOrg`; a purge-client error → `502` and `DeleteOrg` NOT called (assert via a stub).

**herald oidc unit:** `MintPurgeToken` produces a token whose verified claims carry `org`, `scope:"org:purge"`, and `products:[all canonical]`.

**cairn / commonplace / ledger unit:** the self-org purge route deletes WHERE org == injected org and is a no-op (200) when empty; rejects a token lacking `org:purge` (403); cairn also removes the on-disk repo dir.

**conformance reap layer (dMon):** provision an org; create a repo (cairn), an issue (ledger), a knowledge entry (commonplace); `DELETE /api/orgs/{id}` via herald with the org name; assert: cairn no longer serves the repo, ledger 404s the issue's project/org, commonplace search no longer returns the entry, and herald `GET /api/orgs` no longer lists the org. Run `-layers all` green.

**DoD:** `DELETE /api/orgs/{id}` (admin + confirm-by-name) wipes herald + cairn + ledger + commonplace for that org via the gateway-routed `org:purge` token; strict (herald identity deleted only after all pillars succeed); idempotent/retryable; `GET /api/orgs` + `-reap` + `Teardown` use it; orphan `cwb-test-*` accrual stops; unit suites green across all four services + conformance; a dMon reap-layer run proves the cascade. NEX-402 closed.

---

## 8. Build sequence (for the implementation plan)

1. herald store: `DeleteOrg` (txn cascade) + `ListOrgs` + interface + unit tests.
2. herald identity: `DeleteOrg`/`ListOrgs` passthrough + `ScopeOrgPurge` + unit tests.
3. herald oidc: `MintPurgeToken` + unit test.
4. herald `internal/purge`: gateway-routed strict purge client + unit tests (stub server).
5. herald adminapi: `GET /api/orgs` + `DELETE /api/orgs/{id}` (confirm-by-name → purge → DeleteOrg) + wiring in `cmd/herald/main.go` (gateway base from issuer) + unit tests.
6. cairn: `DELETE /api/org` self-org purge (org:purge) + unit tests.
7. commonplace: `DELETE /api/org` self-org purge (org:purge) + unit tests.
8. ledger: `DELETE /api/org` self-org purge (org:purge) + unit tests.
9. cwb-conformance: rewire `Teardown` + `-reap` to herald; add the reap layer.
10. deploy: rebuild + redeploy herald + cairn + ledger + commonplace on dMon; run `-layers all` (incl. reap) green; verify orphan accrual stops; close NEX-402.
