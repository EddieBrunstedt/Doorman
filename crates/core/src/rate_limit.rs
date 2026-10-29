use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::audit::{AuditDispatch, AuditEventKind};
use crate::email::EmailAddress;
use crate::error::{Error, Result, StorageResult};
use crate::session::SessionContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RateLimit {
    LoginStartPerIp,
    LoginFinishPerIp,
    LoginFinishPerPasskey,
    SignupRequestPerIp,
    SignupRequestPerEmail,
    RecoveryRequestPerIp,
    RecoveryRequestPerEmail,
    RecoveryRequestPerEmailDaily,
    RecoveryRequestGlobal,
}

impl RateLimit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoginStartPerIp => "login_start_per_ip",
            Self::LoginFinishPerIp => "login_finish_per_ip",
            Self::LoginFinishPerPasskey => "login_finish_per_passkey",
            Self::SignupRequestPerIp => "signup_request_per_ip",
            Self::SignupRequestPerEmail => "signup_request_per_email",
            Self::RecoveryRequestPerIp => "recovery_request_per_ip",
            Self::RecoveryRequestPerEmail => "recovery_request_per_email",
            Self::RecoveryRequestPerEmailDaily => "recovery_request_per_email_daily",
            Self::RecoveryRequestGlobal => "recovery_request_global",
        }
    }

    // No limit's name contains `:`, so a key can't belong to two limits.
    fn charging(self, value: &str) -> (Self, RateLimitKey) {
        (self, RateLimitKey(format!("{}:{value}", self.as_str())))
    }

    fn charging_everyone(self) -> (Self, RateLimitKey) {
        (self, RateLimitKey(self.as_str().to_owned()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimits {
    pub login_start_per_ip: Option<RateLimitPolicy>,
    pub login_finish_per_ip: Option<RateLimitPolicy>,
    pub login_finish_per_passkey: Option<RateLimitPolicy>,
    pub signup_request_per_ip: Option<RateLimitPolicy>,
    pub signup_request_per_email: Option<RateLimitPolicy>,
    pub recovery_request_per_ip: Option<RateLimitPolicy>,
    pub recovery_request_per_email: Option<RateLimitPolicy>,
    pub recovery_request_per_email_daily: Option<RateLimitPolicy>,
    pub recovery_request_global: Option<RateLimitPolicy>,
}

impl RateLimits {
    pub const fn disabled() -> Self {
        Self {
            login_start_per_ip: None,
            login_finish_per_ip: None,
            login_finish_per_passkey: None,
            signup_request_per_ip: None,
            signup_request_per_email: None,
            recovery_request_per_ip: None,
            recovery_request_per_email: None,
            recovery_request_per_email_daily: None,
            recovery_request_global: None,
        }
    }

    pub fn policy(&self, limit: RateLimit) -> Option<RateLimitPolicy> {
        match limit {
            RateLimit::LoginStartPerIp => self.login_start_per_ip,
            RateLimit::LoginFinishPerIp => self.login_finish_per_ip,
            RateLimit::LoginFinishPerPasskey => self.login_finish_per_passkey,
            RateLimit::SignupRequestPerIp => self.signup_request_per_ip,
            RateLimit::SignupRequestPerEmail => self.signup_request_per_email,
            RateLimit::RecoveryRequestPerIp => self.recovery_request_per_ip,
            RateLimit::RecoveryRequestPerEmail => self.recovery_request_per_email,
            RateLimit::RecoveryRequestPerEmailDaily => self.recovery_request_per_email_daily,
            RateLimit::RecoveryRequestGlobal => self.recovery_request_global,
        }
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        const MINUTE: Duration = Duration::from_secs(60);
        const HOUR: Duration = Duration::from_secs(60 * 60);
        const DAY: Duration = Duration::from_secs(60 * 60 * 24);
        Self {
            login_start_per_ip: Some(RateLimitPolicy::new(60, MINUTE)),
            login_finish_per_ip: Some(RateLimitPolicy::new(60, MINUTE)),
            login_finish_per_passkey: Some(RateLimitPolicy::new(30, MINUTE)),
            signup_request_per_ip: Some(RateLimitPolicy::new(5, HOUR)),
            signup_request_per_email: Some(RateLimitPolicy::new(3, HOUR)),
            recovery_request_per_ip: Some(RateLimitPolicy::new(20, HOUR)),
            recovery_request_per_email: Some(RateLimitPolicy::new(5, HOUR)),
            recovery_request_per_email_daily: Some(RateLimitPolicy::new(10, DAY)),
            recovery_request_global: None,
        }
    }
}

// Built once per core, so its size costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum RateLimiting {
    Enforced {
        limiter: Arc<dyn RateLimiter>,
        limits: RateLimits,
    },
    Disabled,
}

impl RateLimiting {
    pub fn enforced(limiter: Arc<dyn RateLimiter>) -> Self {
        Self::Enforced {
            limiter,
            limits: RateLimits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    pub max_attempts: u32,
    pub window: Duration,
}

impl RateLimitPolicy {
    pub const fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey(String);

impl RateLimitKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited { retry_after: Duration },
}

impl RateLimitDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check_and_charge(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision>;
}

pub(crate) enum Attempt<'a> {
    LoginStart,
    LoginFinish { passkey: &'a [u8] },
    SignupRequest { email: &'a EmailAddress },
    RecoveryRequest { email: &'a EmailAddress },
}

impl Attempt<'_> {
    // In the order they're charged: an attempt refused by one limit isn't charged to the next.
    fn charges(&self, context: &SessionContext) -> Vec<(RateLimit, RateLimitKey)> {
        let ip = context.ip().to_string();
        match self {
            Self::LoginStart => vec![RateLimit::LoginStartPerIp.charging(&ip)],
            Self::LoginFinish { passkey } => vec![
                RateLimit::LoginFinishPerIp.charging(&ip),
                RateLimit::LoginFinishPerPasskey.charging(&URL_SAFE_NO_PAD.encode(passkey)),
            ],
            Self::SignupRequest { email } => vec![
                RateLimit::SignupRequestPerIp.charging(&ip),
                RateLimit::SignupRequestPerEmail.charging(email.as_str()),
            ],
            Self::RecoveryRequest { email } => vec![
                RateLimit::RecoveryRequestPerIp.charging(&ip),
                RateLimit::RecoveryRequestPerEmail.charging(email.as_str()),
                RateLimit::RecoveryRequestPerEmailDaily.charging(email.as_str()),
                RateLimit::RecoveryRequestGlobal.charging_everyone(),
            ],
        }
    }
}

#[derive(Clone)]
pub(crate) struct RateLimitEnforcer {
    rate_limiting: RateLimiting,
    audit: AuditDispatch,
}

impl RateLimitEnforcer {
    pub(crate) fn new(rate_limiting: RateLimiting, audit: AuditDispatch) -> Self {
        Self {
            rate_limiting,
            audit,
        }
    }

    pub(crate) async fn enforce(
        &self,
        context: &SessionContext,
        attempt: Attempt<'_>,
    ) -> Result<()> {
        let RateLimiting::Enforced { limiter, limits } = &self.rate_limiting else {
            return Ok(());
        };
        for (limit, key) in attempt.charges(context) {
            let Some(policy) = limits.policy(limit) else {
                continue;
            };
            if let RateLimitDecision::Limited { retry_after } =
                limiter.check_and_charge(&key, policy).await?
            {
                self.audit
                    .emit(context, AuditEventKind::RateLimited { limit })
                    .await;
                return Err(Error::RateLimited { retry_after });
            }
        }
        Ok(())
    }
}
