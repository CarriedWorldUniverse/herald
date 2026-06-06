# herald: reject duplicate casket pubkey (NEX-426) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a casket public key map to exactly one agent — herald rejects (409) registering a pubkey already bound to another agent, enforced by a partial-unique index + an identity-layer pre-check.

**Architecture:** Partial-unique index on `user.casket_fingerprint` (excludes scopeless humans) as the hard guarantee; an identity pre-check via `GetUserByCasketFingerprint` for the clean common-case 409; `CreateUser` maps the SQLite unique-violation to `store.ErrDuplicateFingerprint`; both registration handlers (which funnel through `adminapi.createAgent`) return 409. A one-time dMon dedup of existing orphan dups precedes the new image so the index applies.

**Tech Stack:** Go 1.26, modernc.org/sqlite, `net/http`, `testing`/`httptest`, kubectl/k3s.

**Spec:** `docs/2026-06-01-herald-dup-pubkey-spec.md`

---

## File structure

- **Modify** `internal/store/schema.sql` — add the partial-unique index.
- **Modify** `internal/store/store.go` — `ErrDuplicateFingerprint`.
- **Modify** `internal/store/sqlite.go` — `CreateUser` maps the unique-violation; a small detection helper.
- **Modify** `internal/store/store_test.go` — store-level dup tests.
- **Modify** `internal/identity/identity.go` — pre-check in `createAgent`.
- **Modify** `internal/identity/identity_test.go` — identity-level dup tests.
- **Modify** `internal/adminapi/adminapi.go` — 409 mapping in `createAgent`.
- **Modify** `internal/adminapi/adminapi_test.go` — endpoint dup tests (admin-create + self-provision).
- **(deploy, Task 4)** one-time dMon DB dedup; no repo change.

---

## Task 1: store — sentinel + index + violation mapping

**Files:**
- Modify: `internal/store/schema.sql`, `internal/store/store.go`, `internal/store/sqlite.go`
- Test: `internal/store/store_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/store/store_test.go` (package `store`; it already constructs a store via `Open(":memory:")` — mirror the existing helper/pattern in that file for opening + creating an org):

```go
func TestCreateUser_DuplicateCasketFingerprintRejected(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	org, err := s.CreateOrg(ctx, "acme")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	// First agent with fingerprint "fp-AAA" succeeds.
	if _, err := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindAgent, DisplayName: "a1",
		CasketFingerprint: "fp-AAA", CasketPubkey: []byte("pub-aaa")}); err != nil {
		t.Fatalf("first agent: %v", err)
	}
	// Second agent with the SAME fingerprint is rejected with ErrDuplicateFingerprint.
	_, err = s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindAgent, DisplayName: "a2",
		CasketFingerprint: "fp-AAA", CasketPubkey: []byte("pub-aaa2")})
	if !errors.Is(err, ErrDuplicateFingerprint) {
		t.Fatalf("dup fingerprint err = %v, want ErrDuplicateFingerprint", err)
	}
	// A distinct fingerprint succeeds.
	if _, err := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindAgent, DisplayName: "a3",
		CasketFingerprint: "fp-BBB", CasketPubkey: []byte("pub-bbb")}); err != nil {
		t.Fatalf("distinct fingerprint: %v", err)
	}
	// Two humans (no fingerprint) both succeed — the partial index exempts empty/NULL.
	if _, err := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindHuman, DisplayName: "h1"}); err != nil {
		t.Fatalf("human 1: %v", err)
	}
	if _, err := s.CreateUser(ctx, User{OrgID: org.ID, Kind: KindHuman, DisplayName: "h2"}); err != nil {
		t.Fatalf("human 2: %v", err)
	}
}
```

Ensure `store_test.go` imports `context` and `errors` (add if missing).

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/store/ -run TestCreateUser_DuplicateCasketFingerprintRejected`
Expected: FAIL — `ErrDuplicateFingerprint` undefined (and, once defined, the second insert currently succeeds because no unique index exists).

- [ ] **Step 3: Add the partial-unique index**

In `internal/store/schema.sql`, after the existing `CREATE INDEX IF NOT EXISTS idx_user_fingerprint ...` line, add:

```sql
-- A casket key is a global identity: at most one agent per fingerprint.
-- Partial (non-empty) so scopeless humans (NULL/empty fingerprint) are exempt.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_fingerprint_uniq
  ON user(casket_fingerprint)
  WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != '';
```

- [ ] **Step 4: Add the sentinel**

In `internal/store/store.go`, near `ErrNotFound`:

```go
// ErrDuplicateFingerprint is returned when an agent registration would reuse a
// casket fingerprint already bound to another agent. A casket key = one agent.
var ErrDuplicateFingerprint = errors.New("store: casket fingerprint already registered")
```

- [ ] **Step 5: Map the violation in `CreateUser`**

In `internal/store/sqlite.go`, change the `CreateUser` error block from:
```go
	if err != nil {
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
```
to:
```go
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed: user.casket_fingerprint") {
			return User{}, ErrDuplicateFingerprint
		}
		return User{}, fmt.Errorf("CreateUser: %w", err)
	}
```
Add `"strings"` to `sqlite.go`'s imports if not already present.

- [ ] **Step 6: Run it to verify it passes**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/store/`
Expected: PASS (the new test + existing store tests).

- [ ] **Step 7: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/store/schema.sql internal/store/store.go internal/store/sqlite.go internal/store/store_test.go
git commit -m "store: partial-unique index on casket_fingerprint + ErrDuplicateFingerprint"
```

---

## Task 2: identity — pre-check in createAgent

**Files:**
- Modify: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/identity/identity_test.go` (package `identity`; uses `store.Open` + `New`):

```go
func TestCreateAgent_DuplicatePubkeyRejected(t *testing.T) {
	ctx := context.Background()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()
	svc := New(s)
	org, _ := s.CreateOrg(ctx, "acme")
	human, _ := svc.CreateHuman(ctx, org.ID, "alice")

	pub, _, _ := casket.DeriveAgentKey([]byte("seed-32-bytes-padded-xxxxxxxxxxx"), "builder")
	if _, err := svc.CreateAgent(ctx, org.ID, "builder", human.ID, pub); err != nil {
		t.Fatalf("first agent: %v", err)
	}
	// Same pubkey again → ErrDuplicateFingerprint (pre-check), even with a different name.
	if _, err := svc.CreateAgent(ctx, org.ID, "builder2", human.ID, pub); !errors.Is(err, store.ErrDuplicateFingerprint) {
		t.Fatalf("dup pubkey err = %v, want store.ErrDuplicateFingerprint", err)
	}
	// A distinct pubkey succeeds.
	pub2, _, _ := casket.DeriveAgentKey([]byte("seed-32-bytes-padded-xxxxxxxxxxx"), "reader")
	if _, err := svc.CreateAgent(ctx, org.ID, "reader", human.ID, pub2); err != nil {
		t.Fatalf("distinct pubkey: %v", err)
	}
}
```

Check `identity_test.go`'s imports include `context`, `errors`, `store`, and the casket import (the package is `github.com/CarriedWorldUniverse/casket-go`, imported as `casket` — match however other identity tests import it; if no existing casket usage, add `casket "github.com/CarriedWorldUniverse/casket-go"`). `DeriveAgentKey` returns `(priv, pub, err)` — take the pub (2nd? confirm: it returns `(priv ed25519.PrivateKey, pub ed25519.PublicKey, err error)` — adjust the assignment to whichever position is the public key; the herald MVP code calls it as `priv, pub, _ := casket.DeriveAgentKey(...)`). Pass `pub` (an `ed25519.PublicKey`) to `CreateAgent`.

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/identity/ -run TestCreateAgent_DuplicatePubkeyRejected`
Expected: FAIL — the second `CreateAgent` currently succeeds (no pre-check) OR fails with a raw constraint error, not `store.ErrDuplicateFingerprint`.

- [ ] **Step 3: Add the pre-check**

In `internal/identity/identity.go`, in `createAgent`, replace the final `return svc.store.CreateUser(ctx, store.User{ ... CasketFingerprint: Fingerprint(pub) ... })` with a version that computes the fingerprint once, pre-checks, then inserts:

```go
	fp := Fingerprint(pub)
	if _, err := svc.store.GetUserByCasketFingerprint(ctx, fp); err == nil {
		return store.User{}, store.ErrDuplicateFingerprint
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.User{}, fmt.Errorf("identity.createAgent: fingerprint check: %w", err)
	}
	return svc.store.CreateUser(ctx, store.User{
		OrgID:             orgID,
		Kind:              store.KindAgent,
		DisplayName:       displayName,
		Status:            status,
		CasketPubkey:      []byte(pub),
		CasketFingerprint: fp,
		ResponsibleHuman:  responsibleHuman,
	})
```
(This replaces the existing trailing `return svc.store.CreateUser(...)` — keep all the field values identical to what's there now; only the fingerprint is hoisted into `fp` and the pre-check is added before it. `errors` and `fmt` are already imported.)

- [ ] **Step 4: Run it to verify it passes**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/identity/`
Expected: PASS (new test + existing identity tests, incl. the golden path).

- [ ] **Step 5: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/identity/identity.go internal/identity/identity_test.go
git commit -m "identity: reject duplicate casket pubkey in createAgent (pre-check)"
```

---

## Task 3: adminapi — 409 on duplicate

**Files:**
- Modify: `internal/adminapi/adminapi.go`
- Test: `internal/adminapi/adminapi_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/adminapi/adminapi_test.go` (mirror the existing helpers — `newStack`, `adminPost`, `doJSON`, and the casket key derivation the golden-path/by-fingerprint tests already use):

```go
func TestAdminCreateAgent_DuplicatePubkey409(t *testing.T) {
	_, _, srv := newStack(t)
	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)
	_, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "alice"})
	humanID, _ := human["id"].(string)

	_, pub, _ := casket.DeriveAgentKey([]byte("seed-32-bytes-padded-xxxxxxxxxxx"), "builder")
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	body := map[string]any{"display_name": "builder", "responsible_human": humanID, "casket_pubkey": pubB64}
	resp, _ := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", body)
	if resp.StatusCode != 200 {
		t.Fatalf("first create = %d, want 200", resp.StatusCode)
	}
	// Same pubkey again → 409.
	body2 := map[string]any{"display_name": "builder2", "responsible_human": humanID, "casket_pubkey": pubB64}
	resp, _ = adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", body2)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("dup create = %d, want 409", resp.StatusCode)
	}
}
```

Match the exact `newStack`/`adminPost`/`doJSON` signatures + the casket import + `base64` import as used elsewhere in the file. (If the agent body field is not `casket_pubkey`, use whatever `agentBody` decodes — check `agentBody` / its `pubkey()` method.)

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/adminapi/ -run TestAdminCreateAgent_DuplicatePubkey409`
Expected: FAIL — the second create currently returns `400` (generic), not `409`.

- [ ] **Step 3: Map the error to 409**

In `internal/adminapi/adminapi.go`, in the `createAgent` helper, change the create-error block from:
```go
	agent, err := create(ctx, orgID, body.DisplayName, responsibleHuman, pub)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
```
to:
```go
	agent, err := create(ctx, orgID, body.DisplayName, responsibleHuman, pub)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateFingerprint) {
			writeErr(w, http.StatusConflict, "casket pubkey already registered to another agent")
			return
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
```
Add `"errors"` to `adminapi.go`'s imports if not present (`store` is already imported).

- [ ] **Step 4: Run it to verify it passes**

Run: `cd /Users/jacinta/Source/herald && go test ./internal/adminapi/ -run TestAdminCreateAgent_DuplicatePubkey409`
Expected: PASS.

- [ ] **Step 5: Add a self-provision dup test**

Self-provision (`POST /api/agents`) flows through the same `createAgent` helper, so it gets 409 too. Add this test (it mirrors `TestGoldenPath`'s setup exactly — `newStack`, `adminPost`, `doJSON`, `mintAgentToken`, `casket.DeriveAgentKey`, `base64` are all already used in the file):

```go
func TestSelfProvision_DuplicatePubkey409(t *testing.T) {
	_, _, srv := newStack(t)
	_, org := adminPost(t, srv.URL+"/api/orgs", map[string]any{"name": "acme"})
	orgID, _ := org["id"].(string)
	_, human := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/humans", map[string]any{"display_name": "jacinta"})
	humanID, _ := human["id"].(string)

	// Bootstrap agent with agent:create, owned by the human; mint its token.
	bsPriv, bsPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "bootstrap")
	_, bsAgent := adminPost(t, srv.URL+"/api/orgs/"+orgID+"/agents", map[string]any{
		"display_name": "bootstrap", "responsible_human": humanID,
		"casket_pubkey": base64.StdEncoding.EncodeToString(bsPub),
		"scopes":        []string{"agent:create"},
	})
	bsID, _ := bsAgent["id"].(string)
	bsTok := mintAgentToken(t, srv.URL, bsID, bsPriv)

	// Self-provision pubkey X -> 200; the SAME pubkey again -> 409.
	_, newPub, _ := casket.DeriveAgentKey([]byte("owner-seed-32-bytes-padded-xxxxx"), "anvil")
	pubB64 := base64.StdEncoding.EncodeToString(newPub)
	resp, _ := doJSON(t, "POST", srv.URL+"/api/agents", bsTok, map[string]any{
		"display_name": "anvil", "casket_pubkey": pubB64, "scopes": []string{"repo:write"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("first self-provision = %d, want 200", resp.StatusCode)
	}
	resp, _ = doJSON(t, "POST", srv.URL+"/api/agents", bsTok, map[string]any{
		"display_name": "anvil2", "casket_pubkey": pubB64, "scopes": []string{"repo:write"},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("dup self-provision = %d, want 409", resp.StatusCode)
	}
}
```

> The seed `"owner-seed-32-bytes-padded-xxxxx"` + slugs match `TestGoldenPath`'s; this derives the same bootstrap/anvil keys, which is fine (separate in-memory store per `newStack`). If `mintAgentToken`'s signature in the file differs, adjust the call to match it.

- [ ] **Step 6: Run the full suite**

Run: `cd /Users/jacinta/Source/herald && go test ./... && go vet ./...`
Expected: PASS + clean across all packages.

- [ ] **Step 7: Commit**

```bash
cd /Users/jacinta/Source/herald
git add internal/adminapi/adminapi.go internal/adminapi/adminapi_test.go
git commit -m "adminapi: 409 on duplicate casket pubkey (admin-create + self-provision)"
```

---

## Task 4: deploy — one-time dMon dedup + rollout (controller)

**Files:** none in the repo. SSH to dMon + GitHub.

- [ ] **Step 1: Open + merge the herald PR**

```bash
cd /Users/jacinta/Source/herald && git push -u origin fix/nex-426-dup-pubkey
gh pr create --base main --title "herald: reject duplicate casket pubkey (NEX-426)" --body "Implements docs/2026-06-01-herald-dup-pubkey-spec.md. Partial-unique index + identity pre-check + 409; one-time dMon dedup precedes rollout."
# wait for 3-platform CI green, then:
gh pr merge <PR#> --squash --delete-branch
```

- [ ] **Step 2: Build the new image on dMon (do NOT roll yet)**

```bash
ssh jacinta@100.91.185.71 'cd ~/src/herald && git checkout main && git pull \
  && podman build -q -f cmd/herald/Containerfile -t localhost/herald:dev . \
  && podman save localhost/herald:dev | sudo k3s ctr images import -'
```

- [ ] **Step 3: Scale herald to 0 + count dups (release the DB)**

```bash
ssh jacinta@100.91.185.71 'sudo kubectl scale deploy/herald -n cwb --replicas=0
  sudo kubectl wait --for=delete pod -l app=herald -n cwb --timeout=60s 2>/dev/null || sleep 5'
```

- [ ] **Step 4: Run the one-time dedup pod**

A pod mounting `herald-data` read-write runs the cleanup against `/data/herald.db`. Only `scope_grant.user_id` references the doomed rows (verified: `responsible_human`/`granted_by` point at humans, not these agents).

```bash
ssh jacinta@100.91.185.71 'sudo kubectl run herald-dedup -n cwb --restart=Never --image=docker.io/library/alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"q\",\"image\":\"docker.io/library/alpine:3.20\",\"command\":[\"sh\",\"-c\",\"apk add --no-cache sqlite >/dev/null 2>&1; sqlite3 /data/herald.db \\\"DELETE FROM scope_grant WHERE user_id IN (SELECT id FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!='' AND rowid NOT IN (SELECT MIN(rowid) FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!='' GROUP BY casket_fingerprint)); DELETE FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!='' AND rowid NOT IN (SELECT MIN(rowid) FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!='' GROUP BY casket_fingerprint); SELECT 'remaining_fp_agents='||count(*) FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!=''; SELECT 'distinct_fp='||count(DISTINCT casket_fingerprint) FROM user WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint!='';\\\"\"],\"volumeMounts\":[{\"name\":\"d\",\"mountPath\":\"/data\"}]}],\"volumes\":[{\"name\":\"d\",\"persistentVolumeClaim\":{\"claimName\":\"herald-data\"}}]}}" >/dev/null 2>&1
  sleep 8
  sudo kubectl logs herald-dedup -n cwb
  sudo kubectl delete pod herald-dedup -n cwb --grace-period=0 >/dev/null 2>&1'
```
Expected: the two SELECTs show `remaining_fp_agents == distinct_fp` (no more dups).

- [ ] **Step 5: Roll the new image (index applies cleanly)**

```bash
ssh jacinta@100.91.185.71 'sudo kubectl scale deploy/herald -n cwb --replicas=1
  sudo kubectl rollout status deploy/herald -n cwb --timeout=120s'
```
Expected: rollout succeeds (the new `Open` creates the unique index without error). If herald crashloops here, a dup slipped the cleanup — re-run Step 4.

- [ ] **Step 6: Verify the index + a green conformance run**

```bash
# index present:
ssh jacinta@100.91.185.71 'sudo kubectl run idxcheck -n cwb --rm -i --restart=Never --image=docker.io/library/alpine:3.20 \
  --overrides="{\"spec\":{\"containers\":[{\"name\":\"q\",\"image\":\"docker.io/library/alpine:3.20\",\"stdin\":true,\"command\":[\"sh\",\"-c\",\"apk add --no-cache sqlite >/dev/null 2>&1; sqlite3 -readonly /data/herald.db \\\".indexes user\\\"\"],\"volumeMounts\":[{\"name\":\"d\",\"mountPath\":\"/data\"}]}],\"volumes\":[{\"name\":\"d\",\"persistentVolumeClaim\":{\"claimName\":\"herald-data\",\"readOnly\":true}}]}}" 2>/dev/null | grep idx_user_fingerprint_uniq'
```
Then trigger the conformance CI (it now guards this) and confirm green:
```bash
gh workflow run conformance.yml --ref main -R CarriedWorldUniverse/cwb-conformance
# or run on dMon directly (CIP + admin token) as in the CI job; expect all 6 layers green
```

- [ ] **Step 7: Close NEX-426**

Add a closing comment (what shipped + the cleanup result) and mark NEX-426 done via the jira MCP.

---

## Notes for the implementer / controller

- **Detection string:** modernc/sqlite surfaces the SQLite message `UNIQUE constraint failed: user.casket_fingerprint` verbatim; the `strings.Contains` check is reliable. If a future SQLite/driver bump changes the text, the test in Task 1 catches it.
- **Pre-check vs index:** the pre-check gives the clean 409 for the normal case; the index is the race/defence-in-depth backstop and the thing that makes the guarantee real. Keep both.
- **Humans unaffected:** `nullStr("")` stores NULL for empty fingerprints, and the index is `WHERE casket_fingerprint IS NOT NULL AND != ''`, so any number of scopeless humans coexist.
- **No skipped tests in the final commit** (Task 3 Step 5): replace the `t.Skip` with the real self-provision dup test or fold the assertion into `TestGoldenPath`.
- **The dedup is destructive but one-time + scoped** (extra duplicate fingerprinted agent rows only, all cwb-test orphans); the before/after counts in Step 4 are the audit. herald is scaled to 0 during it so there's no writer contention.
- **YAGNI:** not touching NEX-402 orphan-org reaping, key rotation, or per-org uniqueness — all named out-of-scope in the spec.
