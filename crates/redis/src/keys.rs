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
        format!("{}session:{}", self.prefix, id.0)
    }

    /// Token-hash index mapping a session's hashed bearer token to its id.
    pub(crate) fn session_hash_index(&self, hash: &TokenHash) -> String {
        format!("{}session:hash:{}", self.prefix, hex(hash))
    }

    /// Per-user SET of session ids.
    pub(crate) fn user_sessions(&self, user_id: UserId) -> String {
        format!("{}user:{}:sessions", self.prefix, user_id.0)
    }

    /// Primary key for a verification token, scoped by purpose so a hash can
    /// never be redeemed under the wrong flow.
    pub(crate) fn vtoken(&self, purpose: VerificationPurpose, hash: &TokenHash) -> String {
        format!(
            "{}vtoken:{}:{}",
            self.prefix,
            purpose_str(purpose),
            hex(hash)
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

    /// Primary key for an in-progress passkey registration ceremony.
    pub(crate) fn pkreg(&self, id: PasskeyChallengeId) -> String {
        format!("{}pkreg:{}", self.prefix, id.0)
    }

    /// Per-user SET of pending registration-ceremony ids.
    pub(crate) fn user_pkregs(&self, user_id: UserId) -> String {
        format!("{}user:{}:pkregs", self.prefix, user_id.0)
    }

    /// Primary key for an in-progress passkey authentication ceremony.
    pub(crate) fn pkauth(&self, id: PasskeyChallengeId) -> String {
        format!("{}pkauth:{}", self.prefix, id.0)
    }
}

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

/// Lowercase hex rendering of a token hash, for use as a key component.
fn hex(hash: &TokenHash) -> String {
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
        assert!(signup.ends_with(&hex(&hash)));

        assert_eq!(
            keys.user_vtokens(user, VerificationPurpose::EmailChange),
            format!("doorman:user:{}:vtokens:email_change", user.0)
        );
    }

    #[test]
    fn hex_is_64_lowercase_chars() {
        let hash = hash_token("x");
        let h = hex(&hash);
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
