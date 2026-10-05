//! Shared enrollment steps behind signup and recovery.
//!
//! Both flows are the same shape: email a single-use link → redeem it to
//! start a passkey registration ceremony → finish the ceremony and issue a
//! session. The link itself, from minting to redemption, is an emailed link
//! of the flow's purpose. This module owns the rest of what is genuinely
//! identical between them — email normalization/validation, the URL
//! template's [`TOKEN_PLACEHOLDER`], the start and finish steps, and the two
//! result types — so [`signup`](crate::signup) and
//! [`recovery`](crate::recovery) read as thin specializations rather than
//! parallel copies.
//!
//! The flows still differ where it matters, and those differences stay in
//! the managers: signup provisions a new unverified user on an unknown
//! email while recovery silently no-ops (enumeration resistance differs by
//! design); recovery additionally sends notification emails, binds a
//! cool-down deadline to the new passkey and session, and emits a richer
//! audit trail.

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

/// Placeholder substituted with the generated token in URL templates. The
/// literal substring `{token}` is replaced with the generated token at
/// send time.
pub const TOKEN_PLACEHOLDER: &str = "{token}";

/// Result of a successful `consume` call on either flow: the caller hands
/// `options` to `navigator.credentials.create` and echoes `challenge_id`
/// back at finish time.
#[derive(Debug)]
pub struct VerificationConsumeOutcome {
    /// Identifier the client echoes back at finish time.
    pub challenge_id: PasskeyChallengeId,
    /// WebAuthn creation options to start registration in the browser.
    pub options: CreationChallengeResponse,
}

/// Result of a successful `finish` call on either flow: a passkey is
/// enrolled and a session is issued for the user.
#[derive(Debug, Clone)]
pub struct EnrollmentOutcome {
    /// The user the passkey was enrolled for.
    pub user: User,
    /// The freshly-issued session.
    pub session: IssuedSession,
    /// The newly-registered credential.
    pub passkey: StoredPasskey,
}

/// Normalize an email for storage and lookup: trim surrounding whitespace
/// and lowercase. Keeps the "find by email" path case-insensitive.
///
/// Every manager stores and looks up addresses in this form, so a host that
/// queries [`UserStore::find_user_by_email`](crate::storage::UserStore::find_user_by_email)
/// directly normalizes through here first.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

/// Cheap structural validation. Not an RFC-compliant parser; just enough
/// to reject obviously malformed input before it reaches storage.
///
/// Control characters are rejected outright: a CR/LF (or NUL) embedded in an
/// address is never legitimate and, left in, would be handed verbatim to the
/// configured [`EmailSender`](crate::email::EmailSender) as the recipient —
/// an email-header-injection vector for any transport that is not itself
/// defensive. Trimming only strips surrounding whitespace, so an interior
/// newline survives normalization; this guard is what closes it library-wide.
pub(crate) fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() || !email.contains('@') || email.chars().any(char::is_control) {
        return Err(Error::InvalidEmail);
    }
    Ok(())
}

/// Dependencies the signup and recovery managers share, and the start and
/// finish steps both flows run. Each manager composes these steps with its
/// own emailed link, policy, events and notices.
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
    /// Build the shared enrollment flow from the [`CoreDeps`] context and
    /// the [`PasskeyManager`] the signup / recovery flows enrol credentials
    /// through.
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

    /// The best-effort sender for the signup / recovery link emails and the
    /// recovery notices, threaded in from
    /// [`CoreDeps::notifier`](crate::context::CoreDeps::notifier).
    pub(crate) fn notifier(&self) -> &SecurityEmailNotifier {
        &self.notifier
    }

    pub(crate) fn records(&self) -> &UserRecords {
        &self.records
    }

    /// Build the flow's emailed links of purpose `P` from the host's
    /// `template` and `lifetime`, validating both.
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

    /// Whether `user_id` has at least one registered passkey.
    pub(crate) async fn has_passkey(&self, user_id: UserId) -> Result<bool> {
        Ok(self.passkey.count_passkeys(user_id).await? > 0)
    }

    pub(crate) fn rate_limiter(&self) -> &Arc<dyn RateLimiter> {
        &self.rate_limiter
    }

    /// Emit one audit event stamped with the current clock and the request
    /// context's IP / user-agent.
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

    /// Record a refused recovery request.
    pub(crate) async fn audit_recovery_failed(
        &self,
        user_id: Option<UserId>,
        reason: RecoveryFailureReason,
        context: &SessionContext,
    ) {
        self.emit(context, AuditEventKind::RecoveryFailed { user_id, reason })
            .await;
    }

    /// Start the passkey registration ceremony a redeemed link leads to.
    pub(crate) async fn start_enrollment(
        &self,
        user_id: UserId,
    ) -> Result<VerificationConsumeOutcome> {
        let (challenge_id, options) = self.passkey.start_enrollment(user_id).await?;
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    /// Finish the registration ceremony under `policy`, enrol the passkey,
    /// issue a session, and audit
    /// [`LoginSucceeded`](AuditEventKind::LoginSucceeded).
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
        // A CR/LF (or NUL) inside the address is an email-header-injection
        // vector once it reaches the transport as the recipient. Normalization
        // trims only the ends, so an interior control char must be rejected
        // here rather than surviving into the `To:` line.
        assert!(validate_email("a@b.com\r\nBcc: victim@evil.com").is_err());
        assert!(validate_email("a@b.com\nSubject: spoofed").is_err());
        assert!(validate_email("a@b.com\0").is_err());
        // A plain address with no control characters still passes.
        assert!(validate_email("user@example.com").is_ok());
    }
}
