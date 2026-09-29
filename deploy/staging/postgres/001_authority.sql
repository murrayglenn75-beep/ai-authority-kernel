CREATE TABLE IF NOT EXISTS aak_used_nonces (
  nonce text PRIMARY KEY,
  used_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS aak_revoked_nonces (
  nonce text PRIMARY KEY,
  reason text NOT NULL
);
CREATE TABLE IF NOT EXISTS aak_integer_budgets (
  bucket text PRIMARY KEY,
  amount bigint NOT NULL CHECK (amount >= 0)
);
CREATE TABLE IF NOT EXISTS aak_transaction_keys (
  idempotency_key text PRIMARY KEY,
  request_hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS aak_resource_versions (
  resource_key text PRIMARY KEY,
  version bigint NOT NULL CHECK (version >= 0)
);
CREATE TABLE IF NOT EXISTS aak_assurance_state (
  name text PRIMARY KEY,
  value bigint NOT NULL CHECK (value >= 0)
);
CREATE TABLE IF NOT EXISTS aak_assurance_replays (
  kind text NOT NULL CHECK (kind IN ('policy', 'identity')),
  identifier text NOT NULL,
  expires_at bigint NOT NULL,
  PRIMARY KEY (kind, identifier)
);
CREATE INDEX IF NOT EXISTS aak_assurance_replays_expiry
  ON aak_assurance_replays(expires_at);
CREATE TABLE IF NOT EXISTS aak_audit_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_hash text UNIQUE NOT NULL,
  previous_hash text NOT NULL,
  event_json jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
