-- Phase 15: passkey device metadata captured at registration.
--
-- Added as a separate migration (rather than editing 0001) so an
-- already-migrated deployment does not trip a checksum mismatch. Defaults
-- keep existing rows valid: no AAGUID, no transports, and not backed up.
ALTER TABLE passkey_credentials ADD COLUMN aaguid TEXT;
ALTER TABLE passkey_credentials ADD COLUMN transports TEXT NOT NULL DEFAULT '';
ALTER TABLE passkey_credentials ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE passkey_credentials ADD COLUMN backup_state INTEGER NOT NULL DEFAULT 0;
