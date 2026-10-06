use std::sync::Arc;
use std::time::Duration;

use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEvent, AuditEventKind, RecoveryFailureReason};
use crate::clock::Clock;
use crate::context::CoreDeps;
use crate::email::SecurityEmailNotifier;
use crate::error::{Error, Result};
use crate::link::{EmailedLink, LinkPurpose};
use crate::passkey::{EnrollmentPolicy, PasskeyManager};
use crate::rate_limit::RateLimiter;
use crate::redeem::Redeemer;
use crate::session::{IssuedSession, SessionContext};
use crate::storage::{PasskeyChallengeId, StoredPasskey, User, UserId, VerificationTokenStore};
use crate::user::UserRecords;

pub const TOKEN_PLACEHOLDER: &str = "{token}";

#[derive(Debug)]
pub struct VerificationConsumeOutcome {
    pub challenge_id: PasskeyChallengeId,
    pub options: CreationChallengeResponse,
}

#[derive(Debug, Clone)]
pub struct EnrollmentOutcome {
    pub user: User,
    pub session: IssuedSession,
    pub passkey: StoredPasskey,
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

#[derive(Clone)]
pub(crate) struct EnrollmentFlow {
    passkey: PasskeyManager,
    records: UserRecords,
    redeemer: Redeemer,
    tokens: Arc<dyn VerificationTokenStore>,
    notifier: SecurityEmailNotifier,
    rate_limiter: Arc<dyn RateLimiter>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
}

impl EnrollmentFlow {
    pub(crate) fn new(deps: &CoreDeps, passkey: PasskeyManager) -> Self {
        Self {
            passkey,
            records: UserRecords::new(deps),
            redeemer: Redeemer::from_deps(deps),
            tokens: deps.verification_tokens.clone(),
            notifier: deps.notifier.clone(),
            rate_limiter: deps.rate_limiter.clone(),
            clock: deps.clock.clone(),
            audit: deps.audit.clone(),
        }
    }

    pub(crate) fn notifier(&self) -> &SecurityEmailNotifier {
        &self.notifier
    }

    pub(crate) fn records(&self) -> &UserRecords {
        &self.records
    }

    pub(crate) fn emailed_link<P: LinkPurpose>(
        &self,
        template: &str,
        lifetime: Duration,
    ) -> std::result::Result<EmailedLink<P>, AssemblyError> {
        EmailedLink::new(
            self.tokens.clone(),
            self.redeemer.clone(),
            self.clock.clone(),
            template,
            lifetime,
        )
    }

    pub(crate) async fn has_passkey(&self, user_id: UserId) -> Result<bool> {
        Ok(self.passkey.count_passkeys(user_id).await? > 0)
    }

    pub(crate) fn rate_limiter(&self) -> &Arc<dyn RateLimiter> {
        &self.rate_limiter
    }

    pub(crate) async fn emit(&self, context: &SessionContext, kind: AuditEventKind) {
        self.audit
            .emit(AuditEvent {
                timestamp: self.clock.now(),
                actor: Actor::Subject {
                    ip: context.ip.clone(),
                    user_agent: context.user_agent.clone(),
                },
                kind,
            })
            .await;
    }

    pub(crate) async fn audit_recovery_failed(
        &self,
        user_id: Option<UserId>,
        reason: RecoveryFailureReason,
        context: &SessionContext,
    ) {
        self.emit(context, AuditEventKind::RecoveryFailed { user_id, reason })
            .await;
    }

    pub(crate) async fn start_enrollment(
        &self,
        user_id: UserId,
        policy: EnrollmentPolicy,
    ) -> Result<VerificationConsumeOutcome> {
        let (challenge_id, options) = self.passkey.start_enrollment(user_id, policy).await?;
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    pub(crate) async fn enroll(
        &self,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        policy: EnrollmentPolicy,
    ) -> Result<EnrollmentOutcome> {
        let outcome = self
            .passkey
            .enroll(challenge_id, response, name, context.clone(), policy)
            .await?;
        self.emit(
            &context,
            AuditEventKind::LoginSucceeded {
                user_id: outcome.user.id,
            },
        )
        .await;
        Ok(outcome)
    }
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
