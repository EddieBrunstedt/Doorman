CREATE TABLE users (
    id BYTEA PRIMARY KEY,
    email TEXT UNIQUE,
    signed_up_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'active',
    disabled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sessions (
    id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip TEXT,
    user_agent TEXT,
    recovery_cool_down_until TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE email_links (
    token_hash BYTEA NOT NULL,
    purpose TEXT NOT NULL,
    user_id BYTEA NOT NULL,
    owner_email TEXT,
    new_email TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, purpose)
);
CREATE UNIQUE INDEX idx_email_links_token_hash ON email_links(token_hash);
CREATE INDEX idx_email_links_expires_at ON email_links(expires_at);

CREATE TABLE passkeys (
    credential_id BYTEA PRIMARY KEY,
    user_id BYTEA NOT NULL,
    passkey BYTEA NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_cool_down_until TIMESTAMPTZ
);
CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);

CREATE TABLE passkey_registrations (
    id BYTEA PRIMARY KEY,
    purpose TEXT NOT NULL,
    user_id BYTEA NOT NULL,
    state BYTEA NOT NULL,
    owner_email TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    recovery_cool_down_until TIMESTAMPTZ
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
