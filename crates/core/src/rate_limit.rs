use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::client_ip::ClientIp;
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

    pub(crate) fn per_client_ip(operation: &'static str, ip: ClientIp) -> Self {
        Self::new(operation).with("ip", ip.to_string())
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

// A limit is skipped only when the host turned its policy off; every key names a value to charge.
pub(crate) async fn enforce(
    rate_limiter: &dyn RateLimiter,
    limits: &[(Option<RateLimitPolicy>, RateLimitKey)],
) -> Result<()> {
    for (policy, key) in limits {
        let Some(policy) = *policy else {
            continue;
        };
        if let RateLimitDecision::Limited { retry_after } =
            rate_limiter.check_and_charge(key, policy).await?
        {
            return Err(Error::RateLimited { retry_after });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct Recording {
        charged: Mutex<Vec<String>>,
        limited: &'static str,
    }

    #[async_trait]
    impl RateLimiter for Recording {
        async fn check_and_charge(
            &self,
            key: &RateLimitKey,
            _policy: RateLimitPolicy,
        ) -> StorageResult<RateLimitDecision> {
            let key = key.canonical();
            let decision = if key == self.limited {
                RateLimitDecision::Limited {
                    retry_after: Duration::from_secs(5),
                }
            } else {
                RateLimitDecision::Allowed
            };
            self.charged.lock().expect("lock").push(key);
            Ok(decision)
        }
    }

    #[tokio::test]
    async fn enforce_skips_only_a_turned_off_policy_and_stops_at_the_first_limit() {
        let policy = Some(RateLimitPolicy::new(1, Duration::from_secs(60)));
        let limiter = Recording {
            charged: Mutex::new(Vec::new()),
            limited: "op|email=a",
        };
        let ip: ClientIp = "192.0.2.1".parse().expect("ip");

        let err = enforce(
            &limiter,
            &[
                (None, RateLimitKey::new("op").with("off", "x")),
                (policy, RateLimitKey::per_client_ip("op", ip)),
                (policy, RateLimitKey::new("op").with("email", "a")),
                (policy, RateLimitKey::new("op")),
            ],
        )
        .await
        .expect_err("limited");

        assert!(matches!(err, Error::RateLimited { retry_after } if retry_after.as_secs() == 5));
        assert_eq!(
            *limiter.charged.lock().expect("lock"),
            ["op|ip=192.0.2.1", "op|email=a"]
        );
    }

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
