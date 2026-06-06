# herald `GET /api/me` (server-authoritative whoami) — design

**Date:** 2026-06-03
**Status:** design (approved in brainstorming)
**Sub-project:** #7a of the server-authoritative-whoami feature — the herald-side endpoint. Multi-repo (cwb-proto + herald + interchange + cwb-conformance + deploy). #7b (`cw whoami --remote`) is a separate cycle that consumes this.

## Goal

Let an authenticated caller fetch their OWN authoritative identity record — the data that is NOT in the access token: display name, kind, status, org name, store-current (authoritative) scopes, and for agents the responsible human + casket fingerprint. This is the server source of truth behind `cw whoami --remote`.

## Approach (decided in brainstorming)

A new `Me` RPC on herald's existing `AdminService`, HTTP-bound `GET /api/me`, reached through the gateway at `<edge>/herald/api/me`. **Identity-derived authz with NO admin scope** — unlike the platform/org-admin RPCs, `Me` returns the *caller's own* record, so it only requires a verified identity (`callerFromCtx`). Chosen over an OIDC-standard `/userinfo` because herald's OIDC layer is go-jose-direct with no userinfo hook and no store handle, whereas the identity service already holds the full record and this fits the proven proto→herald→interchange→conformance→cw mesh flow.

## Grounding (verified in the herald codebase)

- `internal/grpcadmin/grpcadmin.go`: `callerFromCtx(ctx) (caller, bool)` reads interchange-injected `cwb-subject`/`cwb-org`/`cwb-scopes` metadata; `caller{Subject, Org, Scopes}`. The `Identity` interface the `adminServer` depends on (`a.s.id`) ALREADY exposes everything `Me` needs:
  - `GetUser(ctx, id) (store.User, error)`
  - `GetOrg(ctx, orgID) (store.Org, error)`
  - `EffectiveScopes(ctx, userID) ([]string, error)` — the authoritative (store-current) scopes, not the token snapshot.
- `store.User{ID, OrgID, Kind, DisplayName, Status, ResponsibleHuman, CasketFingerprint, ...}` (`Kind`/`Status` are typed → `string(...)`). `store.Org{ID, Name, ...}`. Agents carry `ResponsibleHuman` + `CasketFingerprint`; both empty for humans.
- No interface widening required. `adminServer{ s *Servers }`; the identity service is `a.s.id`.
- The known gotcha (NEX, #1a): a new AdminService RPC is **501/Unimplemented at the edge** until interchange is rebuilt against the new cwb-proto and redeployed — the cairn/herald-side deploy alone is not enough. `cwb-conform -layers` takes `all` OR a comma-list of real layer names (`all` is a sole keyword).

## Scope

**In:** the `Me` RPC + `UserInfo`/`MeRequest`/`MeResponse` messages in cwb-proto; the herald handler; the interchange rebuild; a conformance subtest; deploy + conformance-green on dMon.

**Out:** the cw client side (`#7b`); list/get of OTHER identities (this is self-only); OIDC `/userinfo`; any new store method (all reads already exist).

---

## cwb-proto — the `Me` RPC + messages

Add to `service AdminService` (in `proto/cwb/herald/v1/herald.proto`):

```protobuf
  // Me — the caller's own authoritative identity record. Any AUTHENTICATED
  // principal (no admin scope); identity-derived from the verified subject.
  rpc Me(MeRequest) returns (MeResponse) {
    option (google.api.http) = {
      get: "/api/me"
      response_body: "user"
    };
  }
```

Messages:
```protobuf
message MeRequest {}
message MeResponse {
  UserInfo user = 1;
}
// UserInfo is a caller's own authoritative identity (agent fields empty for humans).
message UserInfo {
  string id = 1;
  string kind = 2;               // "human" | "agent"
  string display_name = 3;
  string org = 4;                // org id
  string org_name = 5;           // enriched via GetOrg
  string status = 6;             // "active" | "blocked" | "pending"
  repeated string scopes = 7;    // authoritative (store-current) scopes
  string responsible_human = 8;  // agent only
  string fingerprint = 9;        // agent only (casket)
}
```

`response_body:"user"` flattens the HTTP body to the bare `UserInfo` (matching cw's bare-decode convention for `CreateOrg`/`CreateHuman`/etc.). Regenerate the Go stubs (the repo's existing proto-gen path).

## herald — the `Me` handler

In `internal/grpcadmin/admin.go`, alongside the other AdminService handlers:

```go
// Me returns the caller's own authoritative identity record. Any authenticated
// principal may call it for themselves — no admin scope (callerFromCtx only).
func (a *adminServer) Me(ctx context.Context, _ *heraldv1.MeRequest) (*heraldv1.MeResponse, error) {
	c, ok := callerFromCtx(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing identity")
	}
	user, err := a.s.id.GetUser(ctx, c.Subject)
	if err != nil {
		return nil, status.Error(codes.NotFound, "identity not found")
	}
	org, err := a.s.id.GetOrg(ctx, user.OrgID)
	if err != nil {
		return nil, status.Error(codes.Internal, "org lookup failed")
	}
	scopes, err := a.s.id.EffectiveScopes(ctx, user.ID)
	if err != nil {
		return nil, status.Error(codes.Internal, "scope lookup failed")
	}
	return &heraldv1.MeResponse{User: &heraldv1.UserInfo{
		Id:               user.ID,
		Kind:             string(user.Kind),
		DisplayName:      user.DisplayName,
		Org:              user.OrgID,
		OrgName:          org.Name,
		Status:           string(user.Status),
		Scopes:           scopes,
		ResponsibleHuman: user.ResponsibleHuman,
		Fingerprint:      user.CasketFingerprint,
	}}, nil
}
```

Unit test (herald `internal/grpcadmin`): in-process, inject a verified caller via `cwb-*` metadata (mirror the existing `grpcadmin_test.go` dial helpers), provision a human + an agent, call `Me`, assert the returned `UserInfo` matches the stored record (human: kind/display/org/org_name/status/scopes, empty agent fields; agent: responsible_human + fingerprint populated).

## interchange — expose the route

Bump interchange's cwb-proto dependency to the version carrying `Me` and rebuild, so its grpc-gateway compiles the `GET /api/me` HTTP↔gRPC route. Without this the edge returns 501. (No interchange logic change — it forwards `/api/me` like every other `/api/*` AdminService route, injecting the `cwb-*` metadata after JWT verify.)

## cwb-conformance — a whoami/me layer subtest

In the herald layer (`conformance/herald/herald_test.go`), add a `Me` subtest using the existing `fixtures.ProvisionOrg` + `wire.Get` pattern:
- As a provisioned HUMAN (e.g. alice): `GET <heraldBase>/api/me` with the human's bearer → assert `id`==alice.ID, `kind`=="human", `org`==org.OrgID, `org_name`==org.OrgName, `status`=="active", `scopes` ⊇ the provisioned scopes, and `responsible_human`/`fingerprint` empty.
- As a provisioned AGENT (e.g. builder): same call with the agent's bearer → assert `kind`=="agent", `responsible_human`==alice.ID (non-empty), `fingerprint` non-empty, scopes ⊇ provisioned.
- Register `t.Run("Me", ...)` in `TestHeraldLayer`.

## Data flow

`cw`/curl `GET <edge>/herald/api/me` (bearer) → interchange verifies the JWT, injects `cwb-subject` → herald `Me` → `GetUser(subject)` + `GetOrg(orgID)` + `EffectiveScopes(id)` → bare `UserInfo` JSON.

## Error handling

- no verified subject (shouldn't happen behind interchange) → `Unauthenticated`.
- subject not in store (deleted mid-session) → `NotFound`.
- org/scope lookup failure → `Internal`.
- All surface through the gateway as the usual JSON error body.

## Testing & rollout

1. cwb-proto: add RPC + messages, regenerate, PR.
2. herald: implement `Me` + unit test; depends on the regenerated stubs.
3. interchange: bump cwb-proto + rebuild, PR.
4. cwb-conformance: add the `Me` subtest, PR.
5. Build + deploy herald AND interchange images to dMon (`podman save | sudo k3s ctr images import -`; `kubectl rollout restart`).
6. `cwb-conform -target dmon -layers all` GREEN (the new `Me` subtest included). A manual `curl -H "Authorization: Bearer <tok>" <edge>/herald/api/me` smoke as a provisioned human + agent.

## Build order

cwb-proto (RPC+messages) → herald (handler+unit, on the new stubs) → interchange (rebuild) → conformance (subtest) → deploy both images → conformance-green. Then #7b (`cw whoami --remote`) consumes the live endpoint.

## Future (deferred → #7b)

`internal/herald.Me()` wrapper + `UserInfo` type in cw; `cw whoami --remote` rendering the authoritative superset; gated live test. (Separate cycle.)
