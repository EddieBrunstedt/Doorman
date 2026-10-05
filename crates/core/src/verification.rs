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
//! design); recovery additionally sends notification emails, binds a
//! cool-down deadline to the new passkey and session, and emits a richer
//! audit trail.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::audit::{Actor, AuditEvent, AuditEventKind, RecoveryFailureReason};
use crate::context::CoreDeps;
use crate::email::{Email, EmailSender, EmailTemplates};
use crate::error::{Error, Result};
use crate::passkey::PasskeyManager;
use crate::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use crate::redeem::Redeemer;
use crate::session::{IssuedSession, SessionContext};
use crate::storage::{
    PasskeyChallengeId, PasskeyCredentialStore, StoredPasskey, User, UserId, VerificationPurpose,
    VerificationToken, VerificationTokenStore,
};
use crate::token::generate_token;
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
pub(crate) fn normalize_email(email: &str) -> String {
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

/// Substitute [`TOKEN_PLACEHOLDER`] in a configured URL template with the
/// generated token.
pub(crate) fn build_url(template: &str, token: &str) -> String {
    template.replace(TOKEN_PLACEHOLDER, token)
}

/// Enforce one rate-limit policy for an `operation` scoped to a single
/// `(dimension, value)` axis. A `None` policy or a `None` value is a no-op
/// (the policy is disabled or there is no value to key on — e.g. an absent
/// client IP). The structured [`RateLimitKey`] names the dimension rather
/// than concatenating it into the operation string, so a backend can layer
/// independent counters per axis.
pub(crate) async fn enforce_rate_limit(
    rate_limiter: &dyn RateLimiter,
    policy: Option<RateLimitPolicy>,
    operation: &'static str,
    dimension: &'static str,
    value: Option<&str>,
) -> Result<()> {
    let (Some(policy), Some(value)) = (policy, value) else {
        return Ok(());
    };
    let key = RateLimitKey::new(operation).with(dimension, value);
    match rate_limiter.check_and_charge(&key, policy).await? {
        RateLimitDecision::Allowed => Ok(()),
        RateLimitDecision::Limited { retry_after } => Err(Error::RateLimited { retry_after }),
    }
}

/// Enforce a list of rate-limit policies in order, short-circuiting on the
/// first rejection. Each entry is `(policy, operation, dimension, value)`
/// with the same semantics as [`enforce_rate_limit`]. `on_reject` runs once,
/// just before the rejecting error is returned — recovery uses it to emit a
/// `RateLimited` audit event; signup passes a no-op.
pub(crate) async fn enforce_all<F, Fut>(
    rate_limiter: &dyn RateLimiter,
    policies: &[(
        Option<RateLimitPolicy>,
        &'static str,
        &'static str,
        Option<&str>,
    )],
    on_reject: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for &(policy, operation, dimension, value) in policies {
        if let Err(err) =
            enforce_rate_limit(rate_limiter, policy, operation, dimension, value).await
        {
            on_reject().await;
            return Err(err);
        }
    }
    Ok(())
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
    new_email: Option<String>,
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
            new_email,
            created_at: now,
            expires_at: now + lifetime,
        })
        .await?;

    Ok(build_url(url_template, &token))
}

/// Which verification flow an [`EnrollmentFlow`] operation is running for.
/// The signup and recovery managers share the consume/finish skeleton; this
/// names the handful of per-flow differences in that skeleton (token
/// purpose, which audit events fire, whether consuming marks the email
/// verified).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlowKind {
    Signup,
    Recovery,
}

impl FlowKind {
    fn purpose(self) -> VerificationPurpose {
        match self {
            FlowKind::Signup => VerificationPurpose::Signup,
            FlowKind::Recovery => VerificationPurpose::Recovery,
        }
    }

    /// Lower-case flow name used in the log lines the skeleton emits.
    fn label(self) -> &'static str {
        match self {
            FlowKind::Signup => "signup",
            FlowKind::Recovery => "recovery",
        }
    }

    fn consumed_event(self, user_id: UserId) -> AuditEventKind {
        match self {
            FlowKind::Signup => AuditEventKind::SignupConsumed { user_id },
            FlowKind::Recovery => AuditEventKind::RecoveryConsumed { user_id },
        }
    }

    /// Whether consuming the token also marks the user's email verified.
    /// Signup treats clicking a link sent to the address as proof of
    /// ownership; recovery runs against an already-verified address, so it
    /// leaves the flag untouched.
    fn marks_email_verified(self) -> bool {
        matches!(self, FlowKind::Signup)
    }
}

/// Recovery-only extras for [`EnrollmentFlow::finish`]. The two always
/// travel together — recovery supplies both, signup supplies neither — so
/// they are bundled into one `Option` rather than two independent ones,
/// making "cooldown without notification" unrepresentable. `cooldown` is
/// the post-recovery deadline stamped onto both the new passkey and the new
/// session; `notification` renders the recovery-completed email sent
/// best-effort once enrollment succeeds.
pub(crate) struct RecoveryFinish<'a> {
    pub cooldown: std::time::Duration,
    pub notification: &'a (dyn Fn(&User) -> Email + Send + Sync),
}

/// Shared dependencies and consume/finish skeleton behind the signup and
/// recovery managers. Both managers hold one of these and delegate to it,
/// passing an internal flow-kind selector plus the per-flow knobs
/// (post-recovery passkey/session cool-down, finish-time notification) that
/// distinguish the two flows. This is what keeps the two managers from
/// being near-identical copies.
#[derive(Clone)]
pub struct EnrollmentFlow {
    passkey: PasskeyManager,
    records: UserRecords,
    redeemer: Redeemer,
    tokens: Arc<dyn VerificationTokenStore>,
    email: Arc<dyn EmailSender>,
    emails: Arc<dyn EmailTemplates>,
    rate_limiter: Arc<dyn RateLimiter>,
}

impl EnrollmentFlow {
    /// Build the shared enrollment flow from the [`CoreDeps`] context and
    /// the [`PasskeyManager`] the signup / recovery flows enrol credentials
    /// through. The session manager, clock, and audit sink are not held
    /// directly — the flow reaches them through its owned `PasskeyManager`,
    /// which already carries the same collaborators, so they live in one
    /// place. The user records, verification-token store, email transport,
    /// email renderer, and rate limiter are taken from `deps`.
    pub fn new(deps: &CoreDeps, passkey: PasskeyManager) -> Self {
        Self {
            passkey,
            records: UserRecords::new(deps),
            redeemer: Redeemer::from_deps(deps),
            tokens: deps.verification_tokens.clone(),
            email: deps.email.clone(),
            emails: deps.emails.clone(),
            rate_limiter: deps.rate_limiter.clone(),
        }
    }

    /// The renderer for the signup / recovery link copy and recovery notices,
    /// threaded in from [`CoreDeps::emails`](crate::context::CoreDeps::emails).
    pub(crate) fn emails(&self) -> &Arc<dyn EmailTemplates> {
        &self.emails
    }

    pub(crate) fn records(&self) -> &UserRecords {
        &self.records
    }

    pub(crate) fn credentials(&self) -> &Arc<dyn PasskeyCredentialStore> {
        self.passkey.credentials()
    }

    pub(crate) fn tokens(&self) -> &Arc<dyn VerificationTokenStore> {
        &self.tokens
    }

    /// Send an email on a best-effort basis: a transport failure is logged
    /// server-side but never propagated to the caller. Both request endpoints
    /// route every send through here so that a bounce or transport error on a
    /// *registered* address cannot surface as a distinct (error) response —
    /// which would re-introduce the enumeration oracle the silent-on-unknown
    /// design exists to close. The caller's response shape is identical whether
    /// the address resolved and whether delivery succeeded, so the only
    /// residual signal is raw send latency (which a host decouples at its
    /// transport layer if it wants to close that too).
    pub(crate) async fn send_best_effort(&self, email: Email, description: &str) {
        if let Err(err) = self.email.send(email).await {
            tracing::warn!(error = %err, description, "email send failed (best-effort)");
        }
    }

    pub(crate) fn rate_limiter(&self) -> &Arc<dyn RateLimiter> {
        &self.rate_limiter
    }

    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.passkey.clock().now()
    }

    /// Emit one audit event stamped with the current clock and the request
    /// context's IP / user-agent.
    pub(crate) async fn emit(&self, context: &SessionContext, kind: AuditEventKind) {
        self.passkey
            .audit()
            .emit(AuditEvent {
                timestamp: self.passkey.clock().now(),
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

    /// Redeem a verification link and start a passkey registration ceremony.
    /// The token is consumed atomically (so a link cannot be replayed); on
    /// signup the click also marks the email verified. A refused link is
    /// audited as [`RedemptionFailed`](AuditEventKind::RedemptionFailed).
    ///
    /// The link is consumed before the ceremony starts, so starting it must
    /// not fail on the per-user pending-registration cap: the user's
    /// unfinished registration ceremonies are dropped first, and the new one
    /// replaces them. A fresh link already supersedes older links of the same
    /// purpose, and its ceremony supersedes theirs the same way.
    pub(crate) async fn consume(
        &self,
        kind: FlowKind,
        token: &str,
        context: SessionContext,
    ) -> Result<VerificationConsumeOutcome> {
        let user = self
            .redeemer
            .enrollment_link(token, kind.purpose(), &context)
            .await?;
        tracing::Span::current().record("user_id", tracing::field::display(user.id));

        if kind.marks_email_verified() {
            // Clicking a link sent to the address proves ownership.
            self.records.mark_email_verified(&user).await?;
        }

        self.passkey
            .invalidate_pending_registrations(user.id)
            .await?;
        let (challenge_id, options) = self.passkey.start_registration(user.id).await?;

        self.emit(&context, kind.consumed_event(user.id)).await;
        tracing::info!(outcome = "consumed", "{} token consumed", kind.label());
        Ok(VerificationConsumeOutcome {
            challenge_id,
            options,
        })
    }

    /// Finish a passkey registration ceremony and issue a session. When
    /// `recovery` is set the new passkey and session share the same
    /// post-recovery cool-down deadline and the recovery-completed email is
    /// sent best-effort once the new passkey is enrolled. Both flows audit
    /// `LoginSucceeded`.
    pub(crate) async fn finish(
        &self,
        kind: FlowKind,
        challenge_id: PasskeyChallengeId,
        response: &RegisterPublicKeyCredential,
        name: Option<String>,
        context: SessionContext,
        recovery: Option<RecoveryFinish<'_>>,
    ) -> Result<EnrollmentOutcome> {
        // The deadline is bound explicitly to the recovery-completion instant
        // (`now + cooldown`) and is the single value applied to both the new
        // passkey and the new session, so the two never disagree and the
        // deadline is never re-derived from a credential/session `created_at`
        // later on.
        let cooldown_until = recovery.as_ref().map(|recovery| {
            let cooldown = chrono::Duration::from_std(recovery.cooldown)
                .expect("recovery cooldown overflows chrono::Duration; configure a smaller value");
            self.passkey.clock().now() + cooldown
        });

        // `cooldown_until` is `Option<DateTime<Utc>>` (`Copy`); the passkey and
        // session creation bodies both take it as an `Option`, so the deadline
        // (or its absence) threads through one call each instead of a
        // Some/None branch per side.
        //
        // Recovery bypasses the per-user credential cap: it is the
        // all-credentials-lost escape hatch, and its single-use email token was
        // already burned in `consume`. Rejecting it at the cap would brick every
        // recovery attempt and leave the user permanently locked out, since they
        // have no working authenticator to sign in and free a slot.
        let bypass_credential_cap = kind == FlowKind::Recovery;
        let passkey = self
            .passkey
            .finish_registration_inner(
                challenge_id,
                response,
                name,
                context.clone(),
                cooldown_until,
                bypass_credential_cap,
            )
            .await?;
        let user = self.records.find(passkey.user_id).await?;

        if kind == FlowKind::Recovery {
            // Close the pre-recovery-challenge bypass: any registration
            // ceremony begun before this recovery completed was minted without
            // the cool-down stamp, so finishing it now would attach a
            // credential outside the cool-down. Drop those pending challenges
            // (the recovery's own challenge was already consumed by
            // `finish_registration*` above, so this only sweeps the dangerous
            // pre-recovery ones). This sweep runs before the recovery session
            // is issued so a sweep failure aborts with `?` while no
            // cool-down-bearing session has been minted, keeping the guarantee
            // hard: a surviving pre-recovery bypass challenge can never coexist
            // with a committed recovery session.
            self.passkey
                .invalidate_pending_registrations(user.id)
                .await?;
        }

        let session = self
            .passkey
            .sessions()
            .issue(user.id, context.clone(), cooldown_until)
            .await?;

        if let Some(recovery) = recovery {
            // Best-effort — a notification-send failure is logged but does
            // not roll back the enrollment (the passkey is already stored).
            self.send_best_effort((recovery.notification)(&user), kind.label())
                .await;
        }

        self.emit(
            &context,
            AuditEventKind::LoginSucceeded { user_id: user.id },
        )
        .await;
        tracing::info!(outcome = "succeeded", "{} finished", kind.label());
        Ok(EnrollmentOutcome {
            user,
            session,
            passkey,
        })
    }
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
