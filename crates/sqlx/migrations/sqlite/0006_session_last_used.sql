-- Three-bound session model: idle expiry that slides on use. `expires_at`
-- becomes the effective, already-min'd deadline and `last_used_at` records
-- when the session last slid it forward. Existing rows backfill
-- `last_used_at = created_at` (never used since issuance); added as a fresh
-- migration rather than editing 0001 so an already-migrated deployment does
-- not trip a checksum mismatch.
--
-- SQLite cannot add a NOT NULL column whose default references another column,
-- so the column is added nullable and every existing row is backfilled from
-- `created_at`. Every insert from this version on always supplies the value.
ALTER TABLE sessions ADD COLUMN last_used_at TEXT;
UPDATE sessions SET last_used_at = created_at WHERE last_used_at IS NULL;
