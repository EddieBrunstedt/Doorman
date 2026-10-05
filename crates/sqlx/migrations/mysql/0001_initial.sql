-- Reference schema for the doorman SQLx + MySQL/MariaDB adapter.
--
-- UUIDs are stored as BINARY(16) and 32-byte token hashes as BINARY(32), to
-- match the raw bytes the shared adapter code binds; opaque credential ids and
-- ceremony blobs are VARBINARY/BLOB. Text columns are VARCHAR/TEXT (utf8mb4)
-- so they decode as `String`; a binary collation would not.
--
-- Timestamps use DATETIME(6), not TIMESTAMP: DATETIME keeps microsecond TTL
-- precision and spans years outside TIMESTAMP's 1970-2038 epoch range. sqlx
-- pins the session time_zone to +00:00, so `DateTime<Utc>` round-trips as UTC.
--
-- InnoDB is required for the foreign keys and for the `SELECT ... FOR UPDATE`
-- row locking the ephemeral stores' atomic take relies on.

CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    email_verified_at DATETIME(6),
    -- The `AccountStatus` enum projected onto a discriminant (`active` /
    -- `disabled`) plus a nullable timestamp carrying `Disabled { at }`.
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    disabled_at DATETIME(6),
    created_at DATETIME(6) NOT NULL,
    updated_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE sessions (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    token_hash BINARY(32) NOT NULL UNIQUE,
    created_at DATETIME(6) NOT NULL,
    -- Three-bound session model: `expires_at` is the effective, already-min'd
    -- deadline; `last_used_at` records when the session last slid it forward.
    last_used_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    ip VARCHAR(45),
    user_agent TEXT,
    recovery_cooldown_until DATETIME(6),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE verification_tokens (
    token_hash BINARY(32) NOT NULL,
    purpose VARCHAR(32) NOT NULL,
    user_id BINARY(16) NOT NULL,
    -- Target address for an email-change token; NULL for signup/recovery.
    new_email VARCHAR(255),
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    PRIMARY KEY (token_hash, purpose),
    CONSTRAINT fk_verification_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_verification_tokens_user_id ON verification_tokens(user_id);
CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens(expires_at);

CREATE TABLE passkey_credentials (
    credential_id VARBINARY(1024) PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    passkey BLOB NOT NULL,
    name VARCHAR(255),
    created_at DATETIME(6) NOT NULL,
    last_used_at DATETIME(6),
    -- Device metadata captured at registration.
    aaguid VARCHAR(36),
    transports VARCHAR(255) NOT NULL DEFAULT '',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_cooldown_until DATETIME(6),
    CONSTRAINT fk_passkey_credentials_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

CREATE TABLE passkey_registrations (
    id BINARY(16) PRIMARY KEY,
    user_id BINARY(16) NOT NULL,
    state BLOB NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    recovery_cooldown_until DATETIME(6),
    CONSTRAINT fk_passkey_registrations_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_passkey_registrations_user_id ON passkey_registrations(user_id);
CREATE INDEX idx_passkey_registrations_expires_at ON passkey_registrations(expires_at);

CREATE TABLE passkey_authentications (
    id BINARY(16) PRIMARY KEY,
    purpose VARCHAR(32) NOT NULL,
    state BLOB NOT NULL,
    created_at DATETIME(6) NOT NULL,
    expires_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_passkey_authentications_expires_at ON passkey_authentications(expires_at);
