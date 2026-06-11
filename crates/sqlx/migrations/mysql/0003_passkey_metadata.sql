-- Phase 15: passkey device metadata captured at registration.
--
-- Added as a separate migration (rather than editing 0001) so an
-- already-migrated deployment does not trip a checksum mismatch. Defaults
-- keep existing rows valid: no AAGUID, no transports, and not backed up.
ALTER TABLE passkey_credentials ADD COLUMN aaguid VARCHAR(36);
ALTER TABLE passkey_credentials ADD COLUMN transports VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE passkey_credentials ADD COLUMN backup_eligible BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE passkey_credentials ADD COLUMN backup_state BOOLEAN NOT NULL DEFAULT FALSE;
