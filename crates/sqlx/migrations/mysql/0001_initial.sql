CREATE TABLE users (
    id BINARY(16) PRIMARY KEY,
    email VARCHAR(255) UNIQUE,
    email_verified_at DATETIME(6),
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
