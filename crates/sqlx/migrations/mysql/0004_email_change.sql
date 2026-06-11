-- Email-change verification tokens carry the address the account is moving
-- to. Nullable so existing signup/recovery tokens (which have no payload)
-- stay valid; added as a fresh migration rather than editing 0001 so an
-- already-migrated deployment does not trip a checksum mismatch.
ALTER TABLE verification_tokens ADD COLUMN new_email VARCHAR(255);
