-- Consolidated reference schema for the doorman libSQL / Turso adapter.
--
-- libSQL speaks SQLite's SQL dialect, so this mirrors the doorman-sqlx SQLite
-- schema in its final shape: every column from every doorman-sqlx migration is
-- folded into one `CREATE TABLE`. Each statement is `IF NOT EXISTS`, so
-- `migrate()` is idempotent and safe to run on every boot against a local file,
-- an embedded replica, or a remote Turso database.
--
-- UUIDs and 32-byte token hashes are stored as BLOB. Timestamps are stored as
-- RFC3339 TEXT, rendered fixed-width (UTC, `Z` suffix, nanosecond precision) so
-- a lexicographic comparison matches chronological order — which is what the
-- `expires_at` range scans in `purge_expired` / `list_for_user` rely on.

CREATE TABLE IF NOT EXISTS users (
    id BLOB PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    recovery_cooldown_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS verification_tokens (
    token_hash BLOB NOT NULL,
    purpose TEXT NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (token_hash, purpose)
);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_verification_tokens_expires_at ON verification_tokens(expires_at);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    credential_id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey BLOB NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    recovery_cooldown_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE IF NOT EXISTS passkey_registrations (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL,
    state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    recovery_cooldown_until TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkey_registrations_expires_at ON passkey_registrations(expires_at);

CREATE TABLE IF NOT EXISTS passkey_authentications (
    id BLOB PRIMARY KEY,
    state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_passkey_authentications_expires_at ON passkey_authentications(expires_at);
