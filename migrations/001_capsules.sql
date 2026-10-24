CREATE TABLE IF NOT EXISTS capsules (
 id text PRIMARY KEY,
 sender_id text NOT NULL,
 recipient_id text NOT NULL,
 binding bytea NOT NULL,
 binding_sha256 text NOT NULL,
 duration_s bigint NOT NULL CHECK(duration_s BETWEEN 1 AND 31536000),
 expires_at timestamptz NOT NULL,
 state text NOT NULL CHECK(state IN ('reserved','sealed','revoked')),
 created_ms bigint,
 unlock_ms bigint,
 descriptor bytea,
 signature bytea,
 kid text,
 nonce bytea,
 ciphertext bytea,
 tag bytea,
 wrapped_key bytea,
 wrapping_kid text,
 wrapping_nonce bytea,
 seal_digest bytea,
 revision bigint NOT NULL DEFAULT 1,
 revoked_at timestamptz,
 CHECK(sender_id <> recipient_id)
);
CREATE TABLE IF NOT EXISTS capsule_participants (
 capsule_id text NOT NULL REFERENCES capsules(id),
 user_id text NOT NULL,
 hidden boolean NOT NULL DEFAULT false,
 opened boolean NOT NULL DEFAULT false,
 PRIMARY KEY(capsule_id,user_id)
);
CREATE TABLE IF NOT EXISTS capsule_idempotency (
 principal text NOT NULL,
 operation text NOT NULL,
 key text NOT NULL,
 request_digest bytea NOT NULL,
 response bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(principal,operation,key)
);
CREATE TABLE IF NOT EXISTS capsule_events (
 id bigserial PRIMARY KEY,
 capsule_id text NOT NULL,
 event text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS capsule_live_wrapping_keys ON capsules(wrapping_kid) WHERE state='sealed';
