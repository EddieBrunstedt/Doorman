pub use crate::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
pub use crate::audit::{
    Actor, AuditEvent, AuditEventKind, AuditSink, NoopAuditSink, OperatorActor,
    RecoveryFailureReason, RedemptionFailureReason, SecretKind,
};
pub use crate::clock::{Clock, SystemClock};
pub use crate::destructive::{DestructiveAction, DestructiveActions};
#[cfg(feature = "file-email")]
pub use crate::email::FileEmailSender;
pub use crate::email::{
    DefaultEmailTemplates, Email, EmailSender, EmailTemplates, SecurityNotices, TerminalEmailSender,
};
pub use crate::email_link::TOKEN_PLACEHOLDER;
pub use crate::error::{Error, Result, StorageError, StorageErrorKind, StorageResult};
pub use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
pub use crate::operator::{NoticePolicy, OperatorManager, OperatorNotice};
pub use crate::passkey::{
    AuthenticationOutcome, PasskeyConfig, PasskeyManager, RegistrationOutcome, StartedRegistration,
};
pub use crate::purge::PurgeSummary;
pub use crate::rate_limit::{
    NoopRateLimiter, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter,
};
pub use crate::reauth::{ReauthAction, ReauthManager, ReauthPolicy, ReauthProof};
pub use crate::recovery::{RecoveryConfig, RecoveryManager, RecoveryRateLimits};
pub use crate::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, SessionManager,
};
pub use crate::signup::{
    OpenSignupPolicy, SignupConfig, SignupDecision, SignupManager, SignupPolicy, SignupRateLimits,
};
pub use crate::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, EmailLinkStore, PasskeyChallengeId,
    PasskeyChallengeStore, PasskeyStore, RegistrationPurpose, Session, SessionId, SessionStore,
    Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash,
    User, UserId, UserStore,
};
pub use crate::user::{UserConfig, UserManager};
