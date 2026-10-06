use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{Error, Result, StorageResult};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    operation: Cow<'static, str>,
    dimensions: Vec<(Cow<'static, str>, String)>,
}

impl RateLimitKey {
    pub fn new(operation: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation: operation.into(),
            dimensions: Vec::new(),
        }
    }

    pub fn with(mut self, name: impl Into<Cow<'static, str>>, value: impl Into<String>) -> Self {
        self.dimensions.push((name.into(), value.into()));
        self
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn dimensions(&self) -> &[(Cow<'static, str>, String)] {
        &self.dimensions
    }

    pub fn canonical(&self) -> String {
        let mut out = String::with_capacity(self.operation.len() + self.dimensions.len() * 16);
        out.push_str(&self.operation);
        for (name, value) in &self.dimensions {
            out.push('|');
            out.push_str(name);
            out.push('=');
            out.push_str(value);
        }
        out
    }
}

impl fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
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

#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check_and_charge(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRateLimiter;

#[async_trait]
impl RateLimiter for NoopRateLimiter {
    async fn check_and_charge(
        &self,
        _key: &RateLimitKey,
        _policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        Ok(RateLimitDecision::Allowed)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_canonical_renders_operation_and_dimensions_in_order() {
        let key = RateLimitKey::new("passkey/authenticate/finish")
            .with("ip", "1.2.3.4")
            .with("passkey", "abc");
        assert_eq!(
            key.canonical(),
            "passkey/authenticate/finish|ip=1.2.3.4|passkey=abc"
        );
        assert_eq!(key.operation(), "passkey/authenticate/finish");
        assert_eq!(key.dimensions().len(), 2);
    }

    #[test]
    fn distinct_dimensions_do_not_collide() {
        let ip = RateLimitKey::new("op").with("ip", "v");
        let user = RateLimitKey::new("op").with("user", "v");
        assert_ne!(ip.canonical(), user.canonical());
        assert_ne!(ip, user);
    }
}
