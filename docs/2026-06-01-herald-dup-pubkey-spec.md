# herald: reject duplicate casket pubkey (NEX-426) — spec

**Status:** approved design · 2026-06-01
**Ticket:** NEX-426 (Bug) · relates NEX-412 (by-fingerprint endpoint)
**Goal:** a casket public key maps to **exactly one** agent. herald rejects registering a pubkey already bound to another agent, so the by-fingerprint lookup (`GET /api/agents/by-fingerprint/{fp}`) that cairn's SSH ingress depends on is provably unambiguous.
**Why now:** herald currently accepts the same casket pubkey on multiple agents (across orgs). The fingerprint is `base64url(sha256(rawEd25519Pub)[:16])`; by-fingerprint assumes one key → one agent, but nothing enforced it. Surfaced by the cwb-conformance work (the cairn layer resolved to the wrong org when two layers shared a key); the fixtures were fixed to use unique keys, but herald should make a collision **impossible to register**, not merely impolite to create.

---

## 1. The one-paragraph architecture

The invariant is enforced at two layers: a **store-level partial-unique index** on `user.casket_fingerprint` (the hard guarantee, race-proof, partial so scopeless humans with no fingerprint don't collide), and an **identity-layer pre-check** (`GetUserByCasketFingerprint`) in the single `createAgent` chokepoint that both registration paths (admin-create and self-provision) flow through, so the common case returns a clean `409 Conflict` rather than a raw constraint error. A SQLite unique-violation on insert (a race past the pre-check) is mapped to the same typed `ErrDuplicateFingerprint`. The live dMon DB already holds ~26 duplicate-fingerprint rows from early conformance runs (all cwb-test orphans); a one-time deploy cleanup removes the extras before the unique index is applied, so herald starts cleanly with no destructive logic baked into its boot path.

```
  register agent (admin-create OR self-provision)
        │
        ▼ identity.createAgent
   GetUserByCasketFingerprint(fp) exists?  ──yes──► ErrDuplicateFingerprint ──► 409
        │ no
        ▼ store.CreateUser
   INSERT ... (UNIQUE partial index on casket_fingerprint)
        │ unique violation (race)? ──► ErrDuplicateFingerprint ──► 409
        ▼ ok → agent created
```

---

## 2. Scope

**IN**
1. A partial-unique index on `user.casket_fingerprint` (excluding NULL/empty — humans).
2. `store.ErrDuplicateFingerprint`; `CreateUser` maps the unique-violation to it.
3. An identity-layer pre-check in `createAgent` returning `ErrDuplicateFingerprint`.
4. `handleAdminCreateAgent` + `handleSelfProvisionAgent` map it to `409 Conflict`.
5. A one-time dMon DB cleanup (delete extra duplicate-fingerprint rows) sequenced before the new image rolls.

**OUT (named future work)**
- The broader NEX-402 orphan-test-org cleanup (block/delete endpoint) — the dedup here is the minimum to make the index valid, not a general orphan reap.
- Re-keying / merging existing real agents — none are affected (only cwb-test orphans duplicate).
- Per-org (rather than global) key uniqueness — rejected; a casket key is a global identity.
- Rotating/replacing an agent's key — a separate capability, not in scope.

---

## 3. Components

**`internal/store/schema.sql`** — add (alongside the existing non-unique `idx_user_fingerprint`, which stays for lookups):
```sql
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_fingerprint_uniq
  ON user(casket_fingerprint)
  WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != '';
```
Global (no org column) → one key, one identity everywhere. Partial → scopeless humans (empty/NULL fingerprint) are exempt and never collide with each other.

**`internal/store`** — `var ErrDuplicateFingerprint = errors.New("store: casket fingerprint already registered")`. In `CreateUser` (SQLite impl), detect the unique-constraint violation on `casket_fingerprint` (SQLite reports `UNIQUE constraint failed: user.casket_fingerprint` / constraint error code) and return `ErrDuplicateFingerprint` (wrapped). Other insert errors are returned as-is.

**`internal/identity`** — in `createAgent`, after the existing validation and before `store.CreateUser`: compute the fingerprint (already done via `Fingerprint(pub)`), call `store.GetUserByCasketFingerprint(fp)`; if it returns a user (no not-found error) → return `store.ErrDuplicateFingerprint` (re-export or reference it). If not-found → proceed. (The pre-check is the friendly path; the index is the race backstop. `createAgent` is shared by `CreateAgent` and `CreateAgentPending`, so both admin-create and self-provision are covered by one change.)

**`internal/adminapi`** — `handleAdminCreateAgent` and `handleSelfProvisionAgent`: when the create returns `errors.Is(err, store.ErrDuplicateFingerprint)`, respond `409 Conflict` (message e.g. "casket pubkey already registered"); other errors keep their current mapping (`400`).

---

## 4. The one-time dMon cleanup (deploy step)

herald's permanent schema gains only the index — **no destructive logic on the boot path**. The existing dup rows are cleared once, during this deploy, in this order:

1. Build + import the new herald image on dMon.
2. `kubectl scale deploy/herald -n cwb --replicas=0` (release the SQLite file).
3. Run a one-off pod mounting the `herald-data` PVC read-write that runs, against `/var/lib/nexus/herald.db`:
   ```sql
   -- drop dependent rows of the doomed duplicates first (no guaranteed FK cascade)
   DELETE FROM scope_grant WHERE user_id IN (
     SELECT id FROM user
      WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != ''
        AND rowid NOT IN (SELECT MIN(rowid) FROM user
                          WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != ''
                          GROUP BY casket_fingerprint));
   -- then the extra duplicate agent rows (keep the lowest rowid per fingerprint)
   DELETE FROM user
    WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != ''
      AND rowid NOT IN (SELECT MIN(rowid) FROM user
                        WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != ''
                        GROUP BY casket_fingerprint);
   ```
   (Verify `org_member` / any other `user_id` FK the same way if present; the implementer checks the schema for FK references to `user(id)` and clears them first or relies on a declared cascade.)
4. `kubectl scale deploy/herald -n cwb --replicas=1` → the new image's `Open` applies the unique index cleanly.
5. Verify the index exists and herald is healthy; a conformance run is green.

The deleted rows are duplicate cwb-test orphan agents; no real agent is affected. This step is one-time and audited (a `SELECT count` before/after confirms exactly the extras were removed).

---

## 5. Error handling

| Condition | Result |
|---|---|
| register agent, fingerprint already exists (pre-check) | `409 Conflict` (ErrDuplicateFingerprint) |
| register agent, fingerprint collides on insert (race) | `409 Conflict` (unique violation → ErrDuplicateFingerprint) |
| register agent, distinct fingerprint | created (unchanged) |
| create human (no fingerprint) | unaffected — partial index exempts empty/NULL |
| other create errors (bad pubkey size, unknown human, …) | unchanged (`400`) |

---

## 6. Testing

**store unit:** insert two agent users with the same `casket_fingerprint` → second returns `ErrDuplicateFingerprint`; two human users (empty fingerprint) both succeed (partial index exempts them); inserting an agent with a fingerprint distinct from all others succeeds.

**identity unit:** `CreateAgent` (or `CreateAgentPending`) twice with the same casket pubkey (same org or different org) → second returns `ErrDuplicateFingerprint` via the pre-check; with distinct pubkeys both succeed; humans are unaffected.

**adminapi unit:** `POST /api/orgs/{org}/agents` with a pubkey already registered → `409`; self-provision (`POST /api/agents`) with a duplicate pubkey → `409`; a distinct pubkey still `200`.

**conformance (no change expected):** the suite uses unique keys per org, so it stays green; a full `-layers all` run after deploy confirms no regression (and the CI guards it going forward).

**DoD:** the partial-unique index exists in herald's schema; registering a duplicate casket pubkey (admin-create or self-provision) returns `409`; humans (no fingerprint) are unaffected; the live dMon dups are cleaned and herald starts with the index applied; unit tests green; a post-deploy conformance run is green. NEX-426 closed.

---

## 7. Build sequence (for the implementation plan)

1. store: `ErrDuplicateFingerprint` + the partial-unique index in `schema.sql` + `CreateUser` violation mapping + store unit tests.
2. identity: pre-check in `createAgent` + identity unit tests.
3. adminapi: `409` mapping in both handlers + adminapi unit tests.
4. deploy: build + the one-time dMon dedup (scale-0 → cleanup pod → scale-1) → verify index + a green conformance run; comment + close NEX-426.
