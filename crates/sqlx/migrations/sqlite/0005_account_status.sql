-- Reversible account disable/suspend. The Rust `AccountStatus` enum is
-- projected onto two columns: a `status` discriminant (`active` / `disabled`)
-- and a nullable `disabled_at` carrying the `Disabled { at }` timestamp.
-- Existing rows backfill to `active` with a NULL `disabled_at`; added as a
-- fresh migration rather than editing 0001 so an already-migrated deployment
-- does not trip a checksum mismatch.
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN disabled_at TEXT;
