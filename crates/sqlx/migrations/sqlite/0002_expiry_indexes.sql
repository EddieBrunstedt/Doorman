-- Index the expiry column on every table the purge sweep scans, matching
-- idx_sessions_expires_at. Without these a `purge_expired` (or the
-- background purge task) full-scans these tables as dead rows accumulate.

CREATE INDEX idx_verification_tokens_expires_at ON verification_tokens(expires_at);
CREATE INDEX idx_passkey_registrations_expires_at ON passkey_registrations(expires_at);
CREATE INDEX idx_passkey_authentications_expires_at ON passkey_authentications(expires_at);
