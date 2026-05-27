//! Rate-limiting primitives.
//!
//! The [`RateLimiter`] trait abstracts the backend so a host can run with
//! the bundled in-memory limiter, swap in a Redis-backed implementation,
//! or use [`NoopRateLimiter`] to disable enforcement entirely. The
//! framework-agnostic managers in this crate (notably
//! [`PasswordAuthManager`](crate::password_auth::PasswordAuthManager))
//! consult a limiter on sensitive operations and surface
//! [`Error::RateLimited`](crate::error::Error::RateLimited) when the
//! configured budget is exhausted.

use std::time::Duration;

use async_trait::async_trait;

use crate::error::StorageResult;

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

/// Diagnostic tag returned by [`RateLimiter::diagnostic_kind`]. Used by the
/// axum builder's startup sanity checks to surface limiters that are not
/// safe in production (`Noop` discards all enforcement; `InMemory` is
/// per-process and underestimates effective rate in multi-replica
/// deployments).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimiterKind {
    /// A host-supplied limiter. The default assumed for any third-party
    /// implementation; no warning is emitted at build time.
    Custom,
    /// [`NoopRateLimiter`] — enforcement disabled.
    Noop,
    /// [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter) — fine
    /// for a single-process deployment, not for multi-replica.
    InMemory,
}

/// Backend interface for charging and enforcing rate-limit policies.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// Charge a single attempt against `key` under `policy`.
    ///
    /// The implementation is responsible for tracking attempts per key
    /// and returning [`RateLimitDecision::Limited`] when `policy` would
    /// be violated. A limiter that errors here is treated as a storage
    /// failure by the calling manager; transient errors should be
    /// retried internally rather than bubbled up.
    async fn check(&self, key: &str, policy: RateLimitPolicy) -> StorageResult<RateLimitDecision>;

    /// Used by the axum builder's startup sanity checks to detect noop /
    /// per-process limiters. Third-party implementations should leave the
    /// default in place.
    #[doc(hidden)]
    fn diagnostic_kind(&self) -> RateLimiterKind {
        RateLimiterKind::Custom
    }
}

/// A limiter that never rejects. Useful as a default when rate limiting
/// is disabled or has not been configured yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopRateLimiter;

#[async_trait]
impl RateLimiter for NoopRateLimiter {
    async fn check(
        &self,
        _key: &str,
        _policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        Ok(RateLimitDecision::Allowed)
    }

    fn diagnostic_kind(&self) -> RateLimiterKind {
        RateLimiterKind::Noop
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn noop_limiter_reports_noop_kind() {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopRateLimiter);
        assert_eq!(limiter.diagnostic_kind(), RateLimiterKind::Noop);
    }

    #[test]
    fn custom_limiter_default_reports_custom_kind() {
        struct MyLimiter;
        #[async_trait]
        impl RateLimiter for MyLimiter {
            async fn check(
                &self,
                _key: &str,
                _policy: RateLimitPolicy,
            ) -> StorageResult<RateLimitDecision> {
                Ok(RateLimitDecision::Allowed)
            }
        }

        let limiter: Arc<dyn RateLimiter> = Arc::new(MyLimiter);
        assert_eq!(limiter.diagnostic_kind(), RateLimiterKind::Custom);
    }
}
