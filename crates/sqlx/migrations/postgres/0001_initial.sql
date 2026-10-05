-- Reference schema for the doorman SQLx+Postgres adapter.
--
-- UUIDs and 32-byte token hashes are stored as BYTEA to match what the
-- shared adapter code binds. Timestamps use TIMESTAMPTZ.

CREATE TABLE users (
    id BYTEA PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified_at TIMESTAMPTZ,
    -- The `AccountStatus` enum projected onto a discriminant (`active` /
    -- `disabled`) plus a nullable timestamp carrying `Disabled { at }`.
    status TEXT NOT NULL DEFAULT 'active',
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    -- Three-bound session model: `expires_at` is the effective, already-min'd
    -- deadline; `last_used_at` records when the session last slid it forward.
    last_used_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip TEXT,
    user_agent TEXT,
    recovery_cooldown_until TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE verification_tokens (
    token_hash BYTEA NOT NULL,
    purpose TEXT NOT NULL,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Target address for an email-change token; NULL for signup/recovery.
    new_email TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (token_hash, purpose)
);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens(expires_at);

CREATE TABLE passkey_credentials (
    credential_id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey BYTEA NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    -- Device metadata captured at registration.
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_cooldown_until TIMESTAMPTZ
);
CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE passkey_registrations (
    id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    recovery_cooldown_until TIMESTAMPTZ
);
CREATE INDEX idx_passkey_registrations_user_id ON passkey_registrations(user_id);
CREATE INDEX idx_passkey_registrations_expires_at ON passkey_registrations(expires_at);

CREATE TABLE passkey_authentications (
    id BYTEA PRIMARY KEY,
    purpose TEXT NOT NULL,
    state BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_passkey_authentications_expires_at ON passkey_authentications(expires_at);
