pub use crate::assembly::{AssemblyError, AuthCore, AuthCoreBuilder};
pub use crate::audit::{
    Actor, AuditEvent, AuditEventKind, AuditSink, NoopAuditSink, OperatorActor,
    RecoveryFailureReason, RedemptionFailureReason, SecretKind, SignupFailureReason,
};
pub use crate::client_ip::ClientIp;
pub use crate::clock::{Clock, SystemClock};
pub use crate::destructive::{CurrentSession, DestructiveAction};
#[cfg(feature = "file-email")]
pub use crate::email::FileEmailSender;
pub use crate::email::{
    DefaultEmailTemplates, Email, EmailContent, EmailSender, EmailTemplates, TerminalEmailSender,
};
pub use crate::email_link::TOKEN_PLACEHOLDER;
pub use crate::error::{Error, Result, StorageError, StorageErrorKind, StorageResult};
pub use crate::metrics::{MetricEvent, MetricSink, NoopMetricSink};
pub use crate::operator::OperatorManager;
pub use crate::passkey::{
    AuthenticationOutcome, PasskeyConfig, PasskeyManager, RegistrationOutcome, StartedRegistration,
};
pub use crate::purge::PurgeSummary;
pub use crate::rate_limit::{
    RateLimit, RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter, RateLimits,
};
pub use crate::reauth::{ReauthAction, ReauthPolicy, ReauthProof};
pub use crate::recovery::{RecoveryConfig, RecoveryManager};
pub use crate::security_notice::{NoticePolicy, OperatorNotice};
pub use crate::session::{
    IssuedSession, ResolvedSession, SessionConfig, SessionContext, SessionManager,
};
pub use crate::signup::{
    OpenSignupPolicy, SignupConfig, SignupDecision, SignupManager, SignupPolicy,
};
pub use crate::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, EmailLinkStore, ExpiringStores,
    PasskeyChallengeId, PasskeyChallengeStore, PasskeyStore, PasskeySummary, RecordStores,
    RegistrationPurpose, Session, SessionId, SessionStore, SessionSummary, SessionTransport,
    Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, TokenHash,
    User, UserId, UserStore,
};
pub use crate::user::{EmailChangeOutcome, UserConfig, UserManager};
