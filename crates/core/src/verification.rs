use webauthn_rs::prelude::CreationChallengeResponse;

use crate::error::{Error, Result};
use crate::storage::PasskeyChallengeId;

pub const TOKEN_PLACEHOLDER: &str = "{token}";

#[derive(Debug)]
pub struct VerificationConsumeOutcome {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub(crate) fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') || email.chars().any(char::is_control) {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn validate_email_rejects_embedded_control_characters() {
        assert!(validate_email("a@b.com\r\nBcc: victim@evil.com").is_err());
        assert!(validate_email("a@b.com\nSubject: spoofed").is_err());
        assert!(validate_email("a@b.com\0").is_err());
        assert!(validate_email("user@example.com").is_ok());
    }
}
