CREATE TABLE IF NOT EXISTS capsule_identities (
    issuer text NOT NULL,
    subject text NOT NULL,
    telegram_user_id bigint NOT NULL CHECK (telegram_user_id > 0),
    PRIMARY KEY (issuer, subject),
    UNIQUE (issuer, telegram_user_id)
);
CREATE TABLE IF NOT EXISTS capsule_auth_transactions (
    id text PRIMARY KEY,
    completion_challenge bytea NOT NULL CHECK (octet_length(completion_challenge) = 32),
    state_hash bytea NOT NULL UNIQUE,
    code_hash bytea,
    pkce_verifier text NOT NULL,
    nonce text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '10 minutes'),
    callback_started boolean NOT NULL DEFAULT false,
    completed boolean NOT NULL DEFAULT false,
    consumed boolean NOT NULL DEFAULT false,
    issuer text,
    subject text,
    telegram_user_id bigint CHECK (telegram_user_id > 0)
);
ALTER TABLE capsule_auth_transactions ADD COLUMN IF NOT EXISTS code_hash bytea;
CREATE UNIQUE INDEX IF NOT EXISTS capsule_auth_code_hash ON capsule_auth_transactions(code_hash);
CREATE INDEX IF NOT EXISTS capsule_auth_transactions_expiry ON capsule_auth_transactions(expires_at);
CREATE TABLE IF NOT EXISTS capsule_session_families (
    id text PRIMARY KEY,
    telegram_user_id bigint NOT NULL CHECK (telegram_user_id > 0),
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp() + interval '30 days'),
    revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS capsule_access_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    family_id text NOT NULL REFERENCES capsule_session_families(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS capsule_access_family ON capsule_access_tokens(family_id);
CREATE TABLE IF NOT EXISTS capsule_refresh_tokens (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    family_id text NOT NULL REFERENCES capsule_session_families(id) ON DELETE CASCADE,
    used boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS capsule_refresh_family ON capsule_refresh_tokens(family_id);
