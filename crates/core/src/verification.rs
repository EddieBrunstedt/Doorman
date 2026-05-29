//! Shared "verification link" primitive behind signup and recovery.
//!
//! Both flows are the same shape: email a single-use, hashed-token link →
//! consume it to start a passkey registration ceremony → finish the
//! ceremony and issue a session. This module owns the pieces that are
//! genuinely identical between them — email normalization/validation, URL
//! templating, token generation, rate-limit enforcement, token issuance,
//! and the two result types — so [`signup`](crate::signup) and
//! [`recovery`](crate::recovery) read as thin specializations rather than
//! parallel copies.
//!
//! The flows still differ where it matters, and those differences stay in
//! the managers: signup provisions a new unverified user on an unknown
//! email while recovery silently no-ops (enumeration resistance differs by
//! design); recovery additionally sends a notification email, issues a
//! cool-down session, and emits a richer audit trail.

use chrono::{DateTime, Utc};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use rand::rngs::OsRng;
use webauthn_rs::prelude::CreationChallengeResponse;

use crate::error::{Error, Result};
use crate::rate_limit::{RateLimitDecision, RateLimitPolicy, RateLimiter};
use crate::session::{IssuedSession, hash_token};
use crate::storage::{
    PasskeyChallengeId, StoredPasskey, TokenHash, User, UserId, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};

/// Length in bytes of a freshly-generated verification token before
/// base64 encoding. 32 bytes is 256 bits of entropy.
const TOKEN_BYTES: usize = 32;

/// Placeholder substituted with the generated token in URL templates. The
/// literal substring `{token}` is replaced with the generated token at
/// send time.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

/// Result of a successful `consume` call on either flow: the caller hands
/// `options` to `navigator.credentials.create` and echoes `challenge_id`
/// back at finish time.
#[derive(Debug)]
pub struct VerificationConsumeOutcome {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

/// Result of a successful `finish` call on either flow: a passkey is
/// enrolled and a session is issued for the user.
#[derive(Debug, Clone)]
pub struct EnrollmentOutcome {
    pub user: User,
    pub session: IssuedSession,
    pub passkey: StoredPasskey,
}

/// Normalize an email for storage and lookup: trim surrounding whitespace
/// and lowercase. Keeps the "find by email" path case-insensitive.
pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Cheap structural validation. Not an RFC-compliant parser; just enough
/// to reject obviously malformed input before it reaches storage.
pub(crate) fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

/// Substitute [`TOKEN_PLACEHOLDER`] in a configured URL template with the
/// generated token.
pub(crate) fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

/// Generate a fresh token and its at-rest hash. The cleartext token goes
/// in the email link; only the hash is persisted.
pub(crate) fn generate_token() -> (String, TokenHash) {
    let mut bytes = [0u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_token(&token);
    (token, hash)
}

/// Enforce one rate-limit policy for a `prefix:scope` key. A `None` policy
/// or `None` scope is a no-op (the policy is disabled or there is no value
/// to key on).
pub(crate) async fn enforce_rate_limit(
    rate_limiter: &dyn RateLimiter,
    policy: Option<RateLimitPolicy>,
    prefix: &str,
    scope: Option<&str>,
) -> Result<()> {
    let (Some(policy), Some(scope)) = (policy, scope) else {
        return Ok(());
    };
    let key = format!("{prefix}:{scope}");
    match rate_limiter.check(&key, policy).await? {
        RateLimitDecision::Allowed => Ok(()),
        RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
    }
}

/// Issue a single-use verification link for `user_id`: drop any prior
/// tokens of the same `purpose` (so a stale link cannot be redeemed after
/// a fresh request), store a freshly-hashed token, and return the rendered
/// URL for the caller to drop into an email. Only the cleartext token
/// leaves this function, embedded in the returned URL.
pub(crate) async fn issue_link(
    tokens: &dyn VerificationTokenStore,
    user_id: UserId,
    purpose: VerificationPurpose,
    token_lifetime: std::time::Duration,
    url_template: &str,
    now: DateTime<Utc>,
) -> Result<String> {
    tokens.delete_tokens_for_user(user_id, purpose).await?;

    let lifetime = chrono::Duration::from_std(token_lifetime).expect(
        "verification token lifetime overflows chrono::Duration; configure a smaller value",
    );
    let (token, token_hash) = generate_token();
    tokens
        .create_token(VerificationToken {
            token_hash,
            user_id,
            purpose,
            created_at: now,
            expires_at: now + lifetime,
        })
        .await?;

    Ok(build_url(url_template, &token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_substitutes_placeholder() {
        let url = build_url("https://x.test/s?token={token}", "abc");
        assert_eq!(url, "https://x.test/s?token=abc");
    }

    #[test]
    fn tokens_are_unique() {
        let (a, ha) = generate_token();
        let (b, hb) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ha, hb);
    }

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  USER@Example.COM "), "user@example.com");
    }

    #[test]
    fn validate_email_rejects_malformed() {
        assert!(validate_email("nope").is_err());
        assert!(validate_email("").is_err());
        assert!(validate_email("a@b").is_ok());
    }
}
