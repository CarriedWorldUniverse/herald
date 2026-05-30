# herald — org ownership + invite model

**Status:** draft for approval · 2026-05-31
**Goal:** let a user create and own an org (GitHub-shaped), and bring others in via admin-distributed invite links scoped to a domain or an email allowlist — replacing the static-admin-token provisioning path with user-identity-driven org governance.
**Why now:** building the cwb-conformance herald layer surfaced that herald's admin/provisioning API can't be reached through the gateway: the gateway requires a herald-issued JWT, but `HERALD_ADMIN_TOKEN` is a static bearer (NEX-401/NEX-405 work). The deeper fix the operator called for is to make "who may create/administer an org" a herald-identity question — a user authenticates, creates an org, becomes its owner, and provisions within it using their own token (a JWT the gateway accepts). This pulls a coherent slice of the org model herald MVP deferred (NEX-376 §9) forward and advances NEX-382.

This is the **org-governance** slice. The **authentication-identity** slice it depends on — human email, email verification, a pluggable Notifier, and 2FA-readiness — lands in path-A (the herald path-A spec is amended for it; see §9). This spec consumes a verified-user identity and focuses on orgs, roles, invites, and re-gated provisioning.

---

## 1. The one-paragraph architecture

A user is a standalone account that can exist briefly with no org. A user with a token creates an org via the normal authenticated API and becomes its **owner**; the static `HERALD_ADMIN_TOKEN` shrinks to a deploy-time bootstrap that seeds only the first user. An owner mints **invite links** — secret tokens carrying a scope policy (a single email **domain**, or a known **email allowlist**), a role, an expiry, and a use cap — and distributes them through their own channels (herald sends nothing). An authenticated, email-verified user follows a link and is attached to that org with the link's role, provided their verified email satisfies the policy. Every user belongs to exactly **one** org (no many-to-many); org governance (`org_role`) is represented distinctly from capability (`scope_grant`). Provisioning within an org (creating agents) is re-gated on the caller's `org_role` instead of the global admin token, so the whole flow authenticates with herald-issued JWTs and passes cleanly through the gateway.

```
  orgless user ──POST /api/orgs (user token)──► owns org  (org_role=owner)
        owner ──POST /api/orgs/{org}/invites──► invite link {domain|email_list, role, exp, max_uses}
                                                       │  (admin distributes out-of-band)
   verified user ──POST /api/invites/{tok}/accept──────┘──► attached to org (org_role=member)
        owner ──POST /api/orgs/{org}/agents──► provision (gated on org_role, not admin token)
```

---

## 2. Scope — what's IN

1. **User can exist orgless.** `user.org_id` becomes nullable — the transient state between account creation (path-A) and creating/joining an org.
2. **User creates + owns an org.** `POST /api/orgs` accepts a *user* token (not the admin token), creates the org, and sets the caller's `org_id` + `org_role=owner`. Rejected if the caller already belongs to an org (single-org invariant).
3. **Invite links with a scope policy.** An owner creates an invite link carrying `policy_type ∈ {domain, email_list}`, `policy_value`, a `role` (default `member`), an `expires_at`, and a `max_uses`. Reusable within its policy until expired or exhausted. Herald returns the link token; **distribution is the admin's job** (their own lists) — herald sends no invite email.
4. **Accept attaches to the org.** An authenticated, **email-verified** user follows the link; herald checks the invite is live (not expired, `uses < max_uses`) and the user's verified email satisfies the policy (domain-suffix match, or membership in the allowlist), then sets the user's `org_id` + `org_role` and increments `uses`.
5. **Provisioning re-gated on role.** `POST /api/orgs/{org}/agents` (and any future human-add) require the caller's `org_role` to be `owner` for that org — enforced from the caller's herald token, not the static admin token.
6. **`org_role` in the token.** Issued tokens carry `org_role` so consumers and herald's own gates reason about governance without a lookup.
7. **Bootstrap shrinks.** `HERALD_ADMIN_TOKEN` survives only to seed the first user account at deploy time; everything after flows through the user→org model.

---

## 3. Data model (delta)

```
org
  (unchanged: id, name, status, created_at)

user
  org_id     TEXT NULL  REFERENCES org(id)   -- WAS NOT NULL; now nullable (orgless transient)
  org_role   TEXT NULL                        -- NEW: 'owner' | 'member' (null when orgless)
  -- email / email_verified / totp_* columns are added by the path-A slice (§9), same table.
  -- (unchanged: id, kind, display_name, status, login_secret, casket_pubkey,
  --  casket_fingerprint, responsible_human, created_at)

org_invite                                    -- NEW
  token        TEXT PRIMARY KEY               -- the link secret (high-entropy)
  org_id       TEXT NOT NULL REFERENCES org(id)
  role         TEXT NOT NULL DEFAULT 'member' -- role granted on accept
  policy_type  TEXT NOT NULL                  -- 'domain' | 'email_list'
  policy_value TEXT NOT NULL                  -- the domain string, OR a JSON array of emails
  expires_at   TEXT NULL                      -- optional expiry
  max_uses     INTEGER NOT NULL DEFAULT 0     -- 0 = unlimited within policy + expiry
  uses         INTEGER NOT NULL DEFAULT 0
  created_by   TEXT NOT NULL REFERENCES user(id)
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))

scope_grant
  (unchanged — capability scopes stay separate from org governance)
```

Invariants:
- A user has **at most one** org (`org_id` null or one value). No membership join-table — single-org is a deliberate choice (revisit only if many-to-many is ever needed).
- `org_role` is null exactly when `org_id` is null.
- `policy_value` is interpreted by `policy_type`: a bare domain (`example.com`, matched as a case-insensitive suffix after `@`) for `domain`; a JSON array of lowercased emails for `email_list`.
- The org creator is the only `owner` for MVP; a promotable distinct `admin` tier is schema-allowed (the `org_role` column is free-form-ish) but not built (YAGNI).

---

## 4. Roles (MVP)

| role | may |
|---|---|
| `owner` | everything in the org: create invite links, provision agents, (future) manage members + delete org |
| `member` | belong to the org; their capabilities come from `scope_grant`, not from the role |

`owner` is set on org creation. `member` is set on invite-accept. A finer `admin` tier (provision but not destroy) and role-change endpoints are deferred (§8).

---

## 5. Auth flows

### 5a. Create an org
1. A path-A-authenticated, email-verified user (orgless) calls `POST /api/orgs` with `{name}` and their bearer token.
2. Herald verifies the token (kind=human, email_verified), checks the user has no `org_id`, creates the org, sets `user.org_id` + `user.org_role=owner`.
3. Subsequent tokens for that user carry `org` + `org_role=owner`.

### 5b. Create an invite link
1. An `owner` calls `POST /api/orgs/{org}/invites` with `{policy_type, policy_value, role?, expires_at?, max_uses?}`.
2. Herald confirms the caller's token has `org=={org}` and `org_role==owner`, generates a high-entropy `token`, stores the `org_invite` row, and returns the link (e.g. `<issuer>/invite/<token>` for a future accept UI, plus the raw token for API accept).
3. The admin distributes the link through their own channels.

### 5c. Accept an invite
1. A path-A-authenticated, email-verified user (orgless) calls `POST /api/invites/{token}/accept`.
2. Herald loads the invite; rejects if missing, expired, or `max_uses>0 && uses>=max_uses`.
3. Herald checks the user's **verified** email against the policy: for `domain`, the email's domain equals `policy_value` (case-insensitive); for `email_list`, the email is in the allowlist.
4. On pass: set the user's `org_id` + `org_role=role`, increment the invite's `uses`. Rejected if the user already belongs to an org (single-org invariant).

### 5d. Provision within an org
1. An `owner` calls `POST /api/orgs/{org}/agents` with their token.
2. Herald confirms `org=={org}` + `org_role==owner` from the token, then creates the agent (existing logic — casket pubkey, responsible_human must be a user in the same org, scopes).
3. The static admin token is **no longer** the provisioning path; it is bootstrap-only.

### 5e. Bootstrap (deploy-time)
1. With `HERALD_ADMIN_TOKEN`, an operator seeds the first user account (`POST /api/users` admin-gated, or a `herald-keytool` subcommand) so there is a human who can then create the first org via 5a.
2. After the first user exists, the admin token is not needed for normal operation.

---

## 6. API surface (delta)

New / changed:
- `POST /api/orgs` — **changed**: now accepts a user token (was admin-gated); sets caller as owner.
- `POST /api/orgs/{org}/invites` — **new**: owner-gated; create an invite link.
- `GET /api/orgs/{org}/invites` — **new**: owner-gated; list active invite links (no secrets beyond token prefix).
- `DELETE /api/orgs/{org}/invites/{token}` — **new**: owner-gated; revoke a link.
- `POST /api/invites/{token}/accept` — **new**: authenticated+verified user; attach to org.
- `POST /api/orgs/{org}/agents` — **changed**: owner-gated (was admin-gated).
- `POST /api/users` — **bootstrap only**: admin-gated; seed the first user. (Routine user creation is path-A signup + invite-accept.)

Token claims gain `org_role` alongside the existing `org`.

---

## 7. Auth gating

Herald derives the caller's identity from their verified token (`sub`, `org`, `org_role`). Org-scoped endpoints check:
- the token's `org` equals the path `{org}`, and
- the token's `org_role` satisfies the endpoint's requirement (`owner` for invites + provisioning).

This is server-side enforcement from the record; the `org_role` claim is a convenience for consumers, not the source of truth (herald re-checks the user's stored role on each governance action).

---

## 8. Explicitly DEFERRED

- **Many-to-many membership** — single-org chosen; revisit only on real need.
- **Email verification, 2FA, the Notifier** — moved to path-A (§9).
- **Finer roles + role management** — a promotable `admin` tier, `POST .../members/{id}/role`, member removal, ownership transfer.
- **Org deletion / lifecycle** — delete/suspend an org and cascade.
- **Org-scoped scope administration UI** — granting capability scopes to members.
- **SSO / external IdP** — herald is the IdP.
- **Invite analytics / per-acceptance audit beyond `uses`**.

---

## 9. Dependency: path-A amendment

This spec consumes a **verified-user identity** that path-A must provide. The path-A spec + plan (herald#12) are amended to add, in path-A's auth-identity scope:

- **`user.email`** (the login identity + the value invite policies match against) and **`user.email_verified`**.
- **Email verification flow** — on signup/accept, herald issues a verification code/link and marks the email verified once confirmed; an unverified user cannot create an org or accept an invite.
- **Pluggable `Notifier` interface** — `SendCode(ctx, email, code, purpose)` with deployment-wired implementations (the nexus email infra / SMTP / a test capture-stub). Herald grows a seam, not a mail server. Used for verification + (future) email 2FA codes.
- **2FA-readiness** — `totp_secret` (nullable) + a `2fa_enabled` flag on the user; the login flow has a second-factor step that is a no-op when disabled. TOTP (RFC 6238, authenticator-app, send-free) is the planned mechanism; the build is deferred but not designed out.

Sequencing: path-A (with this amendment) lands first; org-ownership layers on top.

---

## 10. Build sequence (for the implementation plan)

1. **Spec + decisions sign-off** (this doc) + the path-A amendment.
2. **Schema migration** — `user.org_id` nullable + `user.org_role`; `org_invite` table. (NEX-405-aware: the conformance herald layer's `fixtures.ProvisionOrg` rewrites to this flow.)
3. **Org creation by user token** — re-gate `POST /api/orgs`; set owner.
4. **Invite links** — create/list/revoke (owner-gated) + the policy model.
5. **Accept invite** — policy matching against the verified email; attach + increment uses.
6. **Re-gate provisioning** on `org_role`; shrink the admin token to bootstrap (`POST /api/users`).
7. **`org_role` in token claims** + consumer-visible.
8. **Update cwb-conformance fixtures** (NEX-404 `ProvisionOrg`) to the user→org→provision flow, unblocking the herald layer (NEX-405) live.

**DoD:** an email-verified user creates an org via their own token through the gateway, mints a domain-scoped invite link, a second verified user accepts it and lands as a member, the owner provisions an agent — all authenticated by herald JWTs through the gateway, with no use of the static admin token beyond seeding the first user.

---

## 11. Open questions for the plan (small, non-blocking)

- **Accept-while-orgless vs join-second-org error** — MVP rejects accept if the user already has an org. Confirm the error shape (409?).
- **Invite token format + link shape** — raw token for API accept; a `<issuer>/invite/<token>` URL anticipates a future accept UI (path-A-adjacent). Pin in the plan.
- **`POST /api/users` bootstrap vs a `herald-keytool seed-user` subcommand** — either seeds the first user; pick the one that keeps the admin token's surface smallest.
- **Domain policy matching** — exact domain only, or allow subdomains? MVP: exact, case-insensitive. Confirm.
- **Where email lives during the path-A amendment vs this spec** — the column is added by path-A; this spec only reads `email`/`email_verified`. Keep the migration ordering clean (path-A migration before org-ownership migration).
