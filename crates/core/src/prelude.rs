pub use crate::account::{AccountConfig, AccountManager};
pub use crate::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
pub use crate::audit::{
    Actor, AuditEvent, AuditEventKind, AuditSink, NoopAuditSink, OperatorActor,
    RecoveryFailureReason, RedemptionFailureReason, SecretKind,
};
pub use crate::cache::{SessionCacheConfig, SessionCachePolicy};
pub use crate::clock::{Clock, SystemClock};
#[cfg(feature = "file-email")]
pub use crate::email::FileEmailSender;
pub use crate::email::{
    DefaultEmailTemplates, Email, EmailSender, EmailTemplates, SecurityEmailNotifier,
    TerminalEmailSender,
};
pub use crate::error::{Error, Result, StorageError, StorageErrorKind, StorageResult};
pub use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
pub use crate::operator::{NotificationPolicy, OperatorManager, OperatorNotice};
pub use crate::passkey::{
    AuthenticationOutcome, PasskeyConfig, PasskeyManager, RegistrationOutcome,
};
pub use crate::purge::PurgeSummary;
pub use crate::rate_limit::{
    NoopRateLimiter, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter,
};
pub use crate::reauth::{ReauthAction, ReauthManager, ReauthPolicy, ReauthProof};
pub use crate::recovery::{
    MAX_COOLDOWN, MIN_COOLDOWN, RecoveryConfig, RecoveryManager, RecoveryRateLimits,
};
pub use crate::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, SessionManager,
};
pub use crate::signup::{
    OpenSignupPolicy, SignupConfig, SignupDecision, SignupManager, SignupPolicy, SignupRateLimits,
};
pub use crate::storage::{
    AuthenticationPurpose, PasskeyChallengeId, PasskeyChallengeStore, PasskeyCredentialStore,
    RegistrationPurpose, Session, SessionId, SessionStore, Storage, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash, User, UserId, UserStore,
    VerificationPurpose, VerificationToken, VerificationTokenStore,
};
pub use crate::verification::{TOKEN_PLACEHOLDER, VerificationConsumeOutcome};
