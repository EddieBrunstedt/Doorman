CREATE TABLE users (
    id BLOB PRIMARY KEY,
    email TEXT UNIQUE,
    signed_up_at TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    disabled_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE sessions (
    id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    recovery_cool_down_until TEXT
);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE email_links (
    token_hash BLOB NOT NULL,
    purpose TEXT NOT NULL,
    user_id BLOB NOT NULL,
    owner_email TEXT,
    new_email TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (user_id, purpose)
);
CREATE UNIQUE INDEX idx_email_links_token_hash ON email_links(token_hash);
CREATE INDEX idx_email_links_expires_at ON email_links(expires_at);

CREATE TABLE passkeys (
    credential_id BLOB PRIMARY KEY,
    user_id BLOB NOT NULL,
    passkey BLOB NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    aaguid TEXT,
    transports TEXT NOT NULL DEFAULT '',
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    recovery_cool_down_until TEXT
);
CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);

CREATE TABLE passkey_registrations (
    id BLOB PRIMARY KEY,
    purpose TEXT NOT NULL,
    user_id BLOB NOT NULL,
    state BLOB NOT NULL,
    owner_email TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    recovery_cool_down_until TEXT
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
