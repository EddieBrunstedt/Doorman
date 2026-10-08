use std::sync::Arc;
use std::time::Duration;

use crate::audit::{AuditDispatch, AuditSink};
use crate::clock::{Clock, SystemClock};
use crate::context::CoreDeps;
use crate::destructive::DestructiveActions;
use crate::email::{DefaultEmailTemplates, EmailSender, EmailTemplates, Mailer};
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::operator::OperatorManager;
use crate::passkey::{PasskeyConfig, PasskeyManager, build_webauthn};
use crate::passkey_registration::PasskeyRegistrations;
use crate::rate_limit::RateLimiter;
use crate::reauth::{ReauthManager, ReauthPolicy};
use crate::recovery::{RecoveryConfig, RecoveryConfigError, RecoveryManager};
use crate::security_notice::{NoticePolicy, SecurityNotices};
use crate::session::{SessionConfig, SessionManager};
use crate::session_records::SessionRecords;
use crate::signup::{SignupConfig, SignupManager};
use crate::storage::Storage;
use crate::user::{UserConfig, UserManager};

pub(crate) const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24 * 365 * 10);

#[derive(Debug, thiserror::Error)]
pub enum AssemblyError {
    #[error("email_sender is required")]
    MissingEmailSender,
    #[error("audit sink is required (pass NoopAuditSink explicitly to discard events)")]
    MissingAuditSink,
    #[error(
        "rate limiter is required (pass InMemoryRateLimiter, a shared backend, or NoopRateLimiter explicitly)"
    )]
    MissingRateLimiter,
    #[error("passkey config is required")]
    MissingPasskeyConfig,
    #[error(
        "a re-authentication decision is required: pass ReauthPolicy::required_for([..]) to gate destructive actions, or ReauthPolicy::disabled() to opt out"
    )]
    ReauthDecisionRequired,
    #[error("passkey manager construction failed: {0}")]
    Passkey(crate::error::Error),
    #[error(
        "{flow} url_template must contain the `{placeholder}` placeholder so the link carries the token"
    )]
    InvalidUrlTemplate {
        flow: &'static str,
        placeholder: &'static str,
    },
    #[error(
        "{flow} url_template is still the stock `{placeholder_host}` placeholder; set a real template via the matching builder method"
    )]
    PlaceholderUrlTemplate {
        flow: &'static str,
        placeholder_host: &'static str,
    },
    #[error("recovery cool-down is misconfigured: {0}")]
    RecoveryCoolDown(#[from] RecoveryConfigError),
    #[error("{field} ({value:?}) must be greater than zero and at most {max:?}")]
    InvalidLifetime {
        field: &'static str,
        value: Duration,
        max: Duration,
    },
    #[error("session idle_timeout ({idle_timeout:?}) is invalid: {reason}")]
    IdleTimeoutInvalid {
        idle_timeout: Duration,
        reason: &'static str,
    },
}

pub(crate) fn validate_lifetime(field: &'static str, value: Duration) -> Result<(), AssemblyError> {
    if value.is_zero() || value > MAX_LIFETIME {
        return Err(AssemblyError::InvalidLifetime {
            field,
            value,
            max: MAX_LIFETIME,
        });
    }
    Ok(())
}

fn validate_idle_timeout(
    idle_timeout: Duration,
    absolute_lifetime: Duration,
) -> Result<(), AssemblyError> {
    if idle_timeout.is_zero() || idle_timeout > MAX_LIFETIME {
        return Err(AssemblyError::IdleTimeoutInvalid {
            idle_timeout,
            reason: "must be greater than zero and at most MAX_LIFETIME",
        });
    }
    if idle_timeout > absolute_lifetime {
        return Err(AssemblyError::IdleTimeoutInvalid {
            idle_timeout,
            reason: "must not exceed the session absolute_lifetime",
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct AuthCore {
    pub sessions: SessionManager,
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub user: UserManager,
    pub reauth: ReauthManager,
    pub operator: OperatorManager,
    pub destructive_actions: DestructiveActions,
}

impl AuthCore {
    pub fn builder(storage: Storage) -> AuthCoreBuilder {
        AuthCoreBuilder::new(storage)
    }
}

pub struct AuthCoreBuilder {
    storage: Storage,
    clock: Option<Arc<dyn Clock>>,
    audit: Option<Arc<dyn AuditSink>>,
    email: Option<Arc<dyn EmailSender>>,
    emails: Option<Arc<dyn EmailTemplates>>,
    rate_limiter: Option<Arc<dyn RateLimiter>>,
    recovery_rate_limiter: Option<Arc<dyn RateLimiter>>,
    metrics: Option<Arc<dyn MetricSink>>,
    session_config: Option<SessionConfig>,
    passkey: Option<PasskeyConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
    user: Option<UserConfig>,
    reauth: Option<ReauthPolicy>,
    notice_policy: Option<NoticePolicy>,
}

impl AuthCoreBuilder {
    fn new(storage: Storage) -> Self {
        Self {
            storage,
            clock: None,
            audit: None,
            email: None,
            emails: None,
            rate_limiter: None,
            recovery_rate_limiter: None,
            metrics: None,
            session_config: None,
            passkey: None,
            signup: None,
            recovery: None,
            user: None,
            reauth: None,
            notice_policy: None,
        }
    }

    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn email(mut self, email: Arc<dyn EmailSender>) -> Self {
        self.email = Some(email);
        self
    }

    pub fn emails(mut self, emails: Arc<dyn EmailTemplates>) -> Self {
        self.emails = Some(emails);
        self
    }

    pub fn limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    pub fn recovery_limiter(mut self, limiter: Arc<dyn RateLimiter>) -> Self {
        self.recovery_rate_limiter = Some(limiter);
        self
    }

    pub fn metrics(mut self, metrics: Arc<dyn MetricSink>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn session(mut self, config: SessionConfig) -> Self {
        self.session_config = Some(config);
        self
    }

    pub fn passkey(mut self, config: PasskeyConfig) -> Self {
        self.passkey = Some(config);
        self
    }

    pub fn signup(mut self, config: SignupConfig) -> Self {
        self.signup = Some(config);
        self
    }

    pub fn recovery(mut self, config: RecoveryConfig) -> Self {
        self.recovery = Some(config);
        self
    }

    pub fn user(mut self, config: UserConfig) -> Self {
        self.user = Some(config);
        self
    }

    pub fn reauthentication(mut self, policy: ReauthPolicy) -> Self {
        self.reauth = Some(policy);
        self
    }

    pub fn notice_policy(mut self, policy: NoticePolicy) -> Self {
        self.notice_policy = Some(policy);
        self
    }

    pub fn build(self) -> Result<AuthCore, AssemblyError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let email: Arc<dyn EmailSender> = self.email.ok_or(AssemblyError::MissingEmailSender)?;
        let passkey_config = self.passkey.ok_or(AssemblyError::MissingPasskeyConfig)?;
        let audit: Arc<dyn AuditSink> = self.audit.ok_or(AssemblyError::MissingAuditSink)?;
        let audit = AuditDispatch::new(audit, clock.clone());
        let limiter: Arc<dyn RateLimiter> =
            self.rate_limiter.ok_or(AssemblyError::MissingRateLimiter)?;
        let metrics: Arc<dyn MetricSink> = self
            .metrics
            .unwrap_or_else(|| Arc::new(NoopMetricSink) as Arc<dyn MetricSink>);
        let session_config = self.session_config.unwrap_or_default();

        let emails: Arc<dyn EmailTemplates> = self
            .emails
            .unwrap_or_else(|| Arc::new(DefaultEmailTemplates));
        let signup_config = self.signup.unwrap_or_default();
        let recovery_config = self.recovery.unwrap_or_default();
        let user_config = self.user.unwrap_or_default();

        validate_lifetime(
            "session absolute_lifetime",
            session_config.absolute_lifetime,
        )?;
        validate_lifetime(
            "passkey challenge_lifetime",
            passkey_config.challenge_lifetime,
        )?;

        if let Some(idle_timeout) = session_config.idle_timeout {
            validate_idle_timeout(idle_timeout, session_config.absolute_lifetime)?;
        }

        let mailer = Mailer::new(email, emails);
        let notices = SecurityNotices::new(
            mailer.clone(),
            self.storage.users.clone(),
            self.notice_policy.unwrap_or_default(),
        );

        let session_records = SessionRecords::new(
            self.storage.sessions.clone(),
            self.storage.users.clone(),
            clock.clone(),
            audit.clone(),
            session_config,
        )?;

        let reauth_policy = self.reauth.ok_or(AssemblyError::ReauthDecisionRequired)?;

        let webauthn = Arc::new(build_webauthn(&passkey_config).map_err(AssemblyError::Passkey)?);

        let reauth = ReauthManager::new(
            &passkey_config,
            &self.storage,
            clock.clone(),
            audit.clone(),
            webauthn.clone(),
        );

        let deps = CoreDeps::new(
            clock.clone(),
            audit,
            mailer,
            notices,
            limiter,
            session_records.clone(),
            self.storage,
        )
        .with_metrics(metrics);

        let sessions = SessionManager::new(&deps);

        let registrations = PasskeyRegistrations::new(&deps, &passkey_config, webauthn.clone());

        let passkey = PasskeyManager::new(&deps, registrations.clone(), passkey_config, webauthn);

        let signup = SignupManager::new(&deps, registrations.clone(), signup_config)?;

        let recovery_deps = match self.recovery_rate_limiter {
            Some(rate_limiter) => CoreDeps {
                rate_limiter,
                ..deps.clone()
            },
            None => deps.clone(),
        };
        let recovery = RecoveryManager::new(&recovery_deps, registrations, recovery_config)?;

        let user = UserManager::new(&deps, user_config)?;

        let operator = OperatorManager::new(&deps, passkey.clone());

        let destructive_actions = DestructiveActions::new(
            session_records,
            reauth.clone(),
            reauth_policy,
            clock,
            sessions.clone(),
            passkey.clone(),
            user.clone(),
        );

        Ok(AuthCore {
            sessions,
            passkey,
            signup,
            recovery,
            user,
            reauth,
            operator,
            destructive_actions,
        })
    }
}
