-- Reference schema for the bauth SQLx+SQLite adapter.
--
-- All UUIDs and 32-byte token hashes are stored as BLOB. Timestamps are
-- stored as TEXT in RFC3339, matching what `sqlx`'s `chrono::DateTime<Utc>`
-- binding emits.

CREATE TABLE users (
    id BLOB PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE password_credentials (
    user_id BLOB PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE verification_tokens (
    token_hash BLOB NOT NULL,
    purpose TEXT NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (token_hash, purpose)
);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);

CREATE TABLE passkey_credentials (
    credential_id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey TEXT NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE passkey_registrations (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE passkey_authentications (
    id BLOB PRIMARY KEY,
    user_id BLOB,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE oauth_identities (
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id BLOB NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (provider, subject)
);
CREATE INDEX idx_oauth_identities_user_id ON oauth_identities(user_id);

CREATE TABLE oauth_states (
    state_id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    link_user_id BLOB,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
