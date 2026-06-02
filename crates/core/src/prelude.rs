//! Common imports for hosts using `bauth-core` directly.
//!
//! ```ignore
//! use bauth_core::prelude::*;
//! ```
//!
//! Brings the storage traits, manager types, configs, and the trait-shaped
//! collaborators (clock, audit, email, rate limiter) into scope in one
//! line. Hosts who want a narrower import surface should reach into the
//! individual modules instead.

pub use crate::account::{AccountConfig, AccountManager};
pub use crate::audit::{
    AuditEvent, AuditEventKind, AuditSink, NoopAuditSink, RecoveryFailureReason,
};
pub use crate::clock::{Clock, SystemClock};
pub use crate::email::{
    BauthEmails, DefaultBauthEmails, Email, EmailSender, FileEmailSender, SecurityEmailNotifier,
    TerminalEmailSender,
};
pub use crate::error::{Error, Result, StorageError, StorageResult};
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
