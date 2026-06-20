//! Common imports for hosts using `doorman-core` directly.
//!
//! ```ignore
//! use doorman_core::prelude::*;
//! ```
//!
//! Brings the storage traits, manager types, configs, and the supporting
//! collaborator traits (clock, audit, email, rate limiter) into scope in
//! one line. Hosts that want a narrower import surface should import from
//! the individual modules instead.

pub use crate::account::{AccountConfig, AccountManager};
pub use crate::audit::{
    Actor, AuditEvent, AuditEventKind, AuditSink, NoopAuditSink, OperatorActor,
    RecoveryFailureReason,
};
pub use crate::clock::{Clock, SystemClock};
#[cfg(feature = "file-email")]
pub use crate::email::FileEmailSender;
pub use crate::email::{
    DefaultEmailTemplates, Email, EmailSender, EmailTemplates, SecurityEmailNotifier,
    TerminalEmailSender,
};
pub use crate::error::{Error, Result, StorageError, StorageResult};
pub use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
pub use crate::operator::{NotificationPolicy, OperatorManager, OperatorNotice};
pub use crate::passkey::{PasskeyConfig, PasskeyManager};
pub use crate::purge::PurgeSummary;
pub use crate::rate_limit::{
    NoopRateLimiter, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter,
};
pub use crate::recovery::{MIN_COOLDOWN, RecoveryConfig, RecoveryManager, RecoveryRateLimits};
pub use crate::session::{
    IssuedSession, SessionConfig, SessionContext, SessionInvalidationHook, SessionManager,
};
pub use crate::signup::{SignupConfig, SignupManager, SignupRateLimits};
pub use crate::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore, Session, SessionId,
    SessionStore, Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration,
    TokenHash, User, UserId, UserStore, VerificationPurpose, VerificationToken,
    VerificationTokenStore,
};
pub use crate::verification::{EnrollmentOutcome, TOKEN_PLACEHOLDER, VerificationConsumeOutcome};
