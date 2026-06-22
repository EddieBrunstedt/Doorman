-- Three-bound session model: idle expiry that slides on use. `expires_at`
-- becomes the effective, already-min'd deadline and `last_used_at` records
-- when the session last slid it forward. Existing rows backfill
-- `last_used_at = created_at` (never used since issuance); added as a fresh
-- migration rather than editing 0001 so an already-migrated deployment does
-- not trip a checksum mismatch.
ALTER TABLE sessions ADD COLUMN last_used_at TIMESTAMPTZ;
UPDATE sessions SET last_used_at = created_at WHERE last_used_at IS NULL;
ALTER TABLE sessions ALTER COLUMN last_used_at SET NOT NULL;
