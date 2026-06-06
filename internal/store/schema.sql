-- herald identity store (MVP). Mirrors the MVP spec §3.
-- org -> users (human|agent, one type) -> scope_grant.
-- Flat org for MVP; the recursive parent/manager tree is deferred (spec §9).

CREATE TABLE IF NOT EXISTS org (
  id          TEXT PRIMARY KEY,                 -- uuid
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'active',    -- active|blocked
  created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user (
  id                 TEXT PRIMARY KEY,           -- uuid = canonical entity id
  org_id             TEXT NOT NULL REFERENCES org(id),
  kind               TEXT NOT NULL,              -- human|agent
  display_name       TEXT NOT NULL,
  status             TEXT NOT NULL DEFAULT 'active',  -- active|blocked
  login_secret       TEXT,                       -- human only (hash); null for agent
  casket_pubkey      BLOB,                       -- agent only (ed25519 pubkey, 32 bytes)
  casket_fingerprint TEXT,                       -- agent only
  responsible_human  TEXT REFERENCES user(id),   -- agent only; the human who answers for it
  created_at         TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_user_org ON user(org_id);
CREATE INDEX IF NOT EXISTS idx_user_responsible ON user(responsible_human);
CREATE INDEX IF NOT EXISTS idx_user_fingerprint ON user(casket_fingerprint);
-- A casket key is a global identity: at most one agent per fingerprint.
-- Partial (non-empty) so scopeless humans (NULL/empty fingerprint) are exempt.
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_fingerprint_uniq
  ON user(casket_fingerprint)
  WHERE casket_fingerprint IS NOT NULL AND casket_fingerprint != '';

CREATE TABLE IF NOT EXISTS scope_grant (
  id         TEXT PRIMARY KEY,                   -- uuid
  user_id    TEXT NOT NULL REFERENCES user(id),
  scope      TEXT NOT NULL,                      -- e.g. "repo:write"
  granted_by TEXT REFERENCES user(id),           -- who granted it (accountability of the grant)
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(user_id, scope)
);

-- Org-scoped external identity issuers and enrolled subjects. A subject may be
-- reused in another org without resolving here; inside one org the tuple maps
-- to exactly one herald user.
CREATE TABLE IF NOT EXISTS issuer (
  id         TEXT PRIMARY KEY,                   -- uuid
  org_id     TEXT NOT NULL REFERENCES org(id),
  kind       TEXT NOT NULL,                      -- e.g. k8s
  ref        TEXT NOT NULL,                      -- operator/provider reference
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(org_id, kind, ref)
);
CREATE INDEX IF NOT EXISTS idx_issuer_org ON issuer(org_id);

CREATE TABLE IF NOT EXISTS federated_binding (
  id         TEXT PRIMARY KEY,                   -- uuid
  org_id     TEXT NOT NULL REFERENCES org(id),
  user_id    TEXT NOT NULL REFERENCES user(id),
  issuer_id  TEXT NOT NULL REFERENCES issuer(id),
  subject    TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(org_id, issuer_id, subject)
);
CREATE INDEX IF NOT EXISTS idx_federated_binding_user ON federated_binding(user_id);

-- Per-org product entitlement (deny-list): a product is ENABLED unless a row
-- with enabled=0 exists. Absent row = enabled. herald is core (never listed).
CREATE TABLE IF NOT EXISTS org_product (
  org_id     TEXT NOT NULL REFERENCES org(id),
  product    TEXT NOT NULL,
  enabled    INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (org_id, product)
);

-- Refresh tokens (rotating). The opaque token handed to a client is
-- "<id>.<secret>"; only sha256(secret) is stored. chain_id groups a rotation
-- lineage so the whole chain can be revoked (logout, or replay of a rotated
-- token). A row is valid when revoked_at IS NULL and expires_at is in future.
CREATE TABLE IF NOT EXISTS refresh_token (
  id          TEXT PRIMARY KEY,                 -- public handle (random hex)
  chain_id    TEXT NOT NULL,                    -- rotation-lineage root id
  token_hash  TEXT NOT NULL,                    -- hex sha256 of the secret
  user_id     TEXT NOT NULL REFERENCES user(id),
  issued_at   TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at  TEXT NOT NULL,                    -- RFC3339 (UTC)
  revoked_at  TEXT                              -- NULL until revoked
);
CREATE INDEX IF NOT EXISTS idx_refresh_chain ON refresh_token(chain_id);
CREATE INDEX IF NOT EXISTS idx_refresh_user  ON refresh_token(user_id);
