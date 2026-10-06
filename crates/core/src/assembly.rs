use std::sync::Arc;
use std::time::Duration;

use crate::account::{AccountConfig, AccountManager};
use crate::audit::AuditSink;
use crate::cache::SessionCacheConfig;
use crate::clock::{Clock, SystemClock};
use crate::context::CoreDeps;
use crate::email::{DefaultEmailTemplates, EmailSender, EmailTemplates, SecurityEmailNotifier};
use crate::metrics::{MetricSink, NoopMetricSink};
use crate::operator::{NotificationPolicy, OperatorManager};
use crate::passkey::{PasskeyConfig, PasskeyManager, build_webauthn};
use crate::rate_limit::RateLimiter;
use crate::reauth::{ReauthManager, ReauthPolicy};
use crate::recovery::{RecoveryConfig, RecoveryConfigError, RecoveryManager};
use crate::session::{SessionConfig, SessionManager};
use crate::signup::{SignupConfig, SignupManager};
use crate::storage::Storage;

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
    #[error("recovery cooldown is misconfigured: {0}")]
    RecoveryCooldown(#[from] RecoveryConfigError),
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
    pub session_manager: SessionManager,
    pub passkey: PasskeyManager,
    pub signup: SignupManager,
    pub recovery: RecoveryManager,
    pub account: AccountManager,
    pub reauth: ReauthManager,
    pub operator: OperatorManager,
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
    cache_config: Option<SessionCacheConfig>,
    passkey: Option<PasskeyConfig>,
    signup: Option<SignupConfig>,
    recovery: Option<RecoveryConfig>,
    account: Option<AccountConfig>,
    reauth: Option<ReauthPolicy>,
    notification_policy: Option<NotificationPolicy>,
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
            cache_config: None,
            passkey: None,
            signup: None,
            recovery: None,
            account: None,
            reauth: None,
            notification_policy: None,
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

    pub fn cache(mut self, config: SessionCacheConfig) -> Self {
        self.cache_config = Some(config);
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

    pub fn account(mut self, config: AccountConfig) -> Self {
        self.account = Some(config);
        self
    }

    pub fn reauthentication(mut self, policy: ReauthPolicy) -> Self {
        self.reauth = Some(policy);
        self
    }

    pub fn notification_policy(mut self, policy: NotificationPolicy) -> Self {
        self.notification_policy = Some(policy);
        self
    }

    pub fn build(self) -> Result<AuthCore, AssemblyError> {
        let clock: Arc<dyn Clock> = self.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let email: Arc<dyn EmailSender> = self.email.ok_or(AssemblyError::MissingEmailSender)?;
        let passkey_config = self.passkey.ok_or(AssemblyError::MissingPasskeyConfig)?;
        let audit: Arc<dyn AuditSink> = self.audit.ok_or(AssemblyError::MissingAuditSink)?;
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
        let account_config = self.account.unwrap_or_default();

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

        let notifier = SecurityEmailNotifier::new(email.clone(), emails.clone());

        let session_manager = SessionManager::new(
            self.storage.sessions.clone(),
            self.storage.users.clone(),
            clock.clone(),
            audit.clone(),
            metrics.clone(),
            session_config,
            self.cache_config.unwrap_or_default(),
        )?;

        let reauth_policy = self.reauth.ok_or(AssemblyError::ReauthDecisionRequired)?;

        let webauthn = Arc::new(build_webauthn(&passkey_config).map_err(AssemblyError::Passkey)?);

        let reauth = ReauthManager::new(
            &passkey_config,
            &self.storage,
            clock.clone(),
            audit.clone(),
            reauth_policy,
            webauthn.clone(),
        );

        let deps = CoreDeps::new(
            clock,
            audit,
            email,
            emails,
            notifier,
            limiter,
            session_manager.clone(),
            reauth.clone(),
            self.storage,
        )
        .with_metrics(metrics);

        let passkey = PasskeyManager::new(&deps, passkey_config, webauthn);

        let signup = SignupManager::new(&deps, passkey.clone(), signup_config)?;

        let recovery_deps = match self.recovery_rate_limiter {
            Some(rate_limiter) => CoreDeps {
                rate_limiter,
                ..deps.clone()
            },
            None => deps.clone(),
        };
        let recovery = RecoveryManager::new(&recovery_deps, passkey.clone(), recovery_config)?;

        let account = AccountManager::new(&deps, account_config)?;

        let operator = OperatorManager::new(
            &deps,
            passkey.clone(),
            self.notification_policy.unwrap_or_default(),
        );

        Ok(AuthCore {
            session_manager,
            passkey,
            signup,
            recovery,
            account,
            reauth,
            operator,
        })
    }
}
