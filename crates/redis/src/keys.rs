//! Key-schema helpers.
//!
//! Every key the adapter touches is namespaced under a configurable prefix
//! (default `doorman:`) so a host can run several logical doorman instances
//! against one server, or share a server with unrelated data, without
//! collisions. The schema mirrors the table in the design doc:
//!
//! | Concern                | Primary key               | Secondary indexes                                              |
//! | ---------------------- | ------------------------- | ------------------------------------------------------------- |
//! | Session                | `session:{id}`            | `session:hash:{hash}` -> id; `user:{uid}:sessions` (SET)      |
//! | Verification token     | `vtoken:{purpose}:{hash}` | `user:{uid}:vtokens:{purpose}` (SET of hashes)                |
//! | Passkey registration   | `pkreg:{id}`              | `user:{uid}:pkregs` (SET of ids)                              |
//! | Passkey authentication | `pkauth:{id}`             | none                                                          |

use std::fmt::Write as _;

use doorman_core::storage::{
    PasskeyChallengeId, SessionId, TokenHash, UserId, VerificationPurpose,
};

/// Builds namespaced Redis keys from a shared prefix.
#[derive(Clone, Debug)]
pub(crate) struct KeySchema {
    prefix: String,
}

impl KeySchema {
    /// Build a schema whose keys are all prefixed with `prefix`.
    pub(crate) fn new(prefix: String) -> Self {
        Self { prefix }
    }

    /// The configured namespace prefix.
    pub(crate) fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Primary key for a session row.
    pub(crate) fn session(&self, id: SessionId) -> String {
        self.session_key_for(&id.0.to_string())
    }

    /// Primary key for a session row from its id rendered as a string. Lets a
    /// caller rebuild the key from a user-set member without re-parsing the
    /// UUID, while guaranteeing the same shape as [`session`](Self::session).
    pub(crate) fn session_key_for(&self, id: &str) -> String {
        format!("{}session:{}", self.prefix, id)
    }

    /// Token-hash index mapping a session's hashed bearer token to its id.
    pub(crate) fn session_hash_index(&self, hash: &TokenHash) -> String {
        format!("{}session:hash:{}", self.prefix, token_hash_hex(hash))
    }

    /// Per-user SET of session ids.
    pub(crate) fn user_sessions(&self, user_id: UserId) -> String {
        format!("{}user:{}:sessions", self.prefix, user_id.0)
    }

    /// `SCAN` pattern matching every per-user session SET, for the purge pass.
    pub(crate) fn user_sessions_pattern(&self) -> String {
        format!("{}user:*:sessions", self.prefix)
    }

    /// Primary key for a verification token, scoped by purpose so a hash can
    /// never be redeemed under the wrong flow.
    pub(crate) fn vtoken(&self, purpose: VerificationPurpose, hash: &TokenHash) -> String {
        self.vtoken_key_for(purpose, &token_hash_hex(hash))
    }

    /// Primary key for a verification token from its purpose and the hex hash
    /// stored as a user-set member; the member-driven counterpart of
    /// [`vtoken`](Self::vtoken).
    pub(crate) fn vtoken_key_for(&self, purpose: VerificationPurpose, hex_hash: &str) -> String {
        format!(
            "{}vtoken:{}:{}",
            self.prefix,
            purpose_str(purpose),
            hex_hash
        )
    }

    /// Per-user, per-purpose SET of verification-token hashes.
    pub(crate) fn user_vtokens(&self, user_id: UserId, purpose: VerificationPurpose) -> String {
        format!(
            "{}user:{}:vtokens:{}",
            self.prefix,
            user_id.0,
            purpose_str(purpose)
        )
    }

    /// `SCAN` pattern matching every per-user verification-token SET of a given
    /// purpose. The purpose is fixed in the pattern (rather than parsed back
    /// out of each matched key) so the purge can rebuild value keys precisely.
    pub(crate) fn user_vtokens_pattern(&self, purpose: VerificationPurpose) -> String {
        format!("{}user:*:vtokens:{}", self.prefix, purpose_str(purpose))
    }

    /// Primary key for an in-progress passkey registration ceremony.
    pub(crate) fn pkreg(&self, id: PasskeyChallengeId) -> String {
        self.pkreg_key_for(&id.0.to_string())
    }

    /// Primary key for a registration ceremony from its id rendered as a
    /// string; the member-driven counterpart of [`pkreg`](Self::pkreg).
    pub(crate) fn pkreg_key_for(&self, id: &str) -> String {
        format!("{}pkreg:{}", self.prefix, id)
    }

    /// Per-user SET of pending registration-ceremony ids.
    pub(crate) fn user_pkregs(&self, user_id: UserId) -> String {
        format!("{}user:{}:pkregs", self.prefix, user_id.0)
    }

    /// `SCAN` pattern matching every per-user registration-ceremony SET.
    pub(crate) fn user_pkregs_pattern(&self) -> String {
        format!("{}user:*:pkregs", self.prefix)
    }

    /// Primary key for an in-progress passkey authentication ceremony.
    pub(crate) fn pkauth(&self, id: PasskeyChallengeId) -> String {
        format!("{}pkauth:{}", self.prefix, id.0)
    }

    /// `SCAN` pattern matching every authentication-ceremony key. These carry
    /// no secondary index (§5.6), so the purge scans them directly.
    pub(crate) fn pkauth_pattern(&self) -> String {
        format!("{}pkauth:*", self.prefix)
    }
}

/// The verification purposes, enumerated so a prefix-scoped purge can iterate
/// every per-purpose index. The compiler keeps this in step with
/// [`VerificationPurpose`] through the exhaustive match in [`purpose_str`].
pub(crate) const ALL_PURPOSES: [VerificationPurpose; 3] = [
    VerificationPurpose::Signup,
    VerificationPurpose::Recovery,
    VerificationPurpose::EmailChange,
];

/// Stable lowercase string for a verification purpose, used in key names.
/// Matches the `snake_case` serde rename on [`VerificationPurpose`] so a key
/// is the same whichever side builds it.
pub(crate) fn purpose_str(purpose: VerificationPurpose) -> &'static str {
    match purpose {
        VerificationPurpose::Signup => "signup",
        VerificationPurpose::Recovery => "recovery",
        VerificationPurpose::EmailChange => "email_change",
    }
}

/// Lowercase hex rendering of a token hash, used both as a key component and as
/// the member stored in the per-user token SETs (so the two always agree).
pub(crate) fn token_hash_hex(hash: &TokenHash) -> String {
    let mut out = String::with_capacity(hash.0.len() * 2);
    for byte in &hash.0 {
        // Writing to a String is infallible.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use doorman_core::session::hash_token;

    #[test]
    fn keys_are_prefixed_and_purpose_scoped() {
        let keys = KeySchema::new("doorman:".to_string());
        let hash = hash_token("a-token");
        let user = UserId::new();

        assert!(
            keys.session_hash_index(&hash)
                .starts_with("doorman:session:hash:")
        );
        assert_eq!(keys.prefix(), "doorman:");

        // The same hash under different purposes yields distinct keys.
        let signup = keys.vtoken(VerificationPurpose::Signup, &hash);
        let recovery = keys.vtoken(VerificationPurpose::Recovery, &hash);
        assert_ne!(signup, recovery);
        assert!(signup.ends_with(&token_hash_hex(&hash)));

        assert_eq!(
            keys.user_vtokens(user, VerificationPurpose::EmailChange),
            format!("doorman:user:{}:vtokens:email_change", user.0)
        );
    }

    #[test]
    fn hex_is_64_lowercase_chars() {
        let hash = hash_token("x");
        let h = token_hash_hex(&hash);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
