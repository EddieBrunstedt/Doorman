-- Reference schema for the bauth SQLx+Postgres adapter.
--
-- UUIDs and 32-byte token hashes are stored as BYTEA to match what the
-- shared adapter code binds. Timestamps use TIMESTAMPTZ.

CREATE TABLE users (
    id BYTEA PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
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
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (token_hash, purpose)
);
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);

CREATE TABLE passkey_credentials (
    credential_id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    passkey TEXT NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    recovery_cooldown_until TIMESTAMPTZ
);
CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE passkey_registrations (
    id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    recovery_cooldown_until TIMESTAMPTZ
);

CREATE TABLE passkey_authentications (
    id BYTEA PRIMARY KEY,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
