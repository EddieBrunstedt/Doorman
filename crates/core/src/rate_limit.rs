//! Rate-limiting primitives.
//!
//! The [`RateLimiter`] trait abstracts the backend so a host can run with
//! the bundled in-memory limiter, swap in a Redis-backed implementation,
//! or use [`NoopRateLimiter`] to disable enforcement entirely. The
//! framework-agnostic managers in this crate (notably
//! [`SignupManager`](crate::signup::SignupManager)) consult a limiter on
//! sensitive operations and surface
//! [`Error::RateLimited`](crate::error::Error::RateLimited) when the
//! configured budget is exhausted.

use std::any::Any;
use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::StorageResult;

/// A structured, multi-dimensional rate-limit key.
///
/// Replaces the opaque `&str` the trait used to take, so layered limits —
/// per-IP, per-account, per-credential — name their dimensions rather than
/// smuggling them into a flat string a backend cannot decompose. The
/// `operation` names the limited action (e.g.
/// `"passkey/authenticate/finish"`); each appended dimension is a
/// `(name, value)` pair such as `("ip", "1.2.3.4")` or
/// `("credential", "<id>")`.
///
/// A backend that keys on a single string (the bundled
/// [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter)) calls
/// [`canonical`](Self::canonical); a smarter backend (per-dimension Redis
/// counters, a sharded store) can read [`operation`](Self::operation) and
/// [`dimensions`](Self::dimensions) directly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    operation: Cow<'static, str>,
    dimensions: Vec<(Cow<'static, str>, String)>,
}

impl RateLimitKey {
    /// Start a key for `operation`. Add the axes the limit is scoped to with
    /// [`with`](Self::with).
    pub fn new(operation: impl Into<Cow<'static, str>>) -> Self {
        Self {
            operation: operation.into(),
            dimensions: Vec::new(),
        }
    }

    /// Append a `(name, value)` dimension, consuming and returning `self` so
    /// calls chain: `RateLimitKey::new("op").with("ip", ip).with("account", id)`.
    pub fn with(mut self, name: impl Into<Cow<'static, str>>, value: impl Into<String>) -> Self {
        self.dimensions.push((name.into(), value.into()));
        self
    }

    /// The limited action this key scopes.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// The ordered `(name, value)` dimensions the limit is keyed on.
    pub fn dimensions(&self) -> &[(Cow<'static, str>, String)] {
        &self.dimensions
    }

    /// Stable single-string rendering for backends that key on one string:
    /// the operation followed by each `|name=value` in order. Two keys render
    /// equal iff they share the same operation and the same ordered
    /// dimensions, so distinct axes never collide into one bucket.
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

/// What a [`RateLimiter::check`] call decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Within budget; the attempt was charged and the caller may proceed.
    Allowed,
    /// Budget exhausted; the caller must wait at least `retry_after`
    /// before another attempt is likely to succeed.
    Limited { retry_after: Duration },
}

impl RateLimitDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// A "no more than `max_attempts` events per `window`" rule.
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

/// Backend interface for charging and enforcing rate-limit policies.
///
/// The [`Any`] supertrait lets a composition layer (e.g. the axum builder's
/// startup sanity checks) downcast a boxed limiter to recognise the bundled
/// [`NoopRateLimiter`] / [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter)
/// defaults; host implementations get the blanket `Any` impl for free.
#[async_trait]
pub trait RateLimiter: Send + Sync + Any {
    /// Charge a single attempt against `key` under `policy`.
    ///
    /// The implementation is responsible for tracking attempts per key
    /// and returning [`RateLimitDecision::Limited`] when `policy` would
    /// be violated. A limiter that errors here is treated as a storage
    /// failure by the calling manager; transient errors should be
    /// retried internally rather than bubbled up.
    ///
    /// The [`RateLimitKey`] is structured (operation + named dimensions); a
    /// single-string backend flattens it with
    /// [`RateLimitKey::canonical`].
    async fn check(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision>;
}

/// A limiter that never rejects. Useful as a default when rate limiting
/// is disabled or has not been configured yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRateLimiter;

#[async_trait]
impl RateLimiter for NoopRateLimiter {
    async fn check(
        &self,
        _key: &RateLimitKey,
        _policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        Ok(RateLimitDecision::Allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::Any;
    use std::sync::Arc;

    #[test]
    fn noop_limiter_downcasts_to_its_concrete_type() {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        assert!((limiter.as_ref() as &dyn Any).is::<NoopRateLimiter>());
    }

    #[test]
    fn key_canonical_renders_operation_and_dimensions_in_order() {
        let key = RateLimitKey::new("passkey/authenticate/finish")
            .with("ip", "1.2.3.4")
            .with("credential", "abc");
        assert_eq!(
            key.canonical(),
            "passkey/authenticate/finish|ip=1.2.3.4|credential=abc"
        );
        assert_eq!(key.operation(), "passkey/authenticate/finish");
        assert_eq!(key.dimensions().len(), 2);
    }

    #[test]
    fn distinct_dimensions_do_not_collide() {
        let ip = RateLimitKey::new("op").with("ip", "v");
        let account = RateLimitKey::new("op").with("account", "v");
        assert_ne!(ip.canonical(), account.canonical());
        assert_ne!(ip, account);
    }

    #[test]
    fn custom_limiter_does_not_masquerade_as_noop() {
        struct MyLimiter;
        #[async_trait]
        impl RateLimiter for MyLimiter {
            async fn check(
                &self,
                _key: &RateLimitKey,
                _policy: RateLimitPolicy,
            ) -> StorageResult<RateLimitDecision> {
                Ok(RateLimitDecision::Allowed)
            }
        }

        let limiter: Arc<dyn RateLimiter> = Arc::new(MyLimiter);
        assert!(!(limiter.as_ref() as &dyn Any).is::<NoopRateLimiter>());
    }
}
