-- Reference schema for the doorman SQLx+SQLite adapter.
--
-- All UUIDs and 32-byte token hashes are stored as BLOB. Timestamps are
-- stored as TEXT in RFC3339, matching what `sqlx`'s `chrono::DateTime<Utc>`
-- binding emits.

CREATE TABLE users (
    id BLOB PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified_at TEXT,
    -- The `AccountStatus` enum projected onto a discriminant (`active` /
    -- `disabled`) plus a nullable timestamp carrying `Disabled { at }`.
    status TEXT NOT NULL DEFAULT 'active',
    disabled_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    -- Three-bound session model: `expires_at` is the effective, already-min'd
    -- deadline; `last_used_at` records when the session last slid it forward.
    last_used_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    recovery_cooldown_until TEXT
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE verification_tokens (
    token_hash BLOB NOT NULL,
    purpose TEXT NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Target address for an email-change token; NULL for signup/recovery.
    new_email TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (token_hash, purpose)
);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens(expires_at);

CREATE TABLE passkey_credentials (
    credential_id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey BLOB NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    -- Device metadata captured at registration.
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    recovery_cooldown_until TEXT
);
CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE passkey_registrations (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    recovery_cooldown_until TEXT
);
CREATE INDEX idx_passkey_registrations_user_id ON passkey_registrations(user_id);
CREATE INDEX idx_passkey_registrations_expires_at ON passkey_registrations(expires_at);

CREATE TABLE passkey_authentications (
    id BLOB PRIMARY KEY,
    purpose TEXT NOT NULL,
    state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX idx_passkey_authentications_expires_at ON passkey_authentications(expires_at);
