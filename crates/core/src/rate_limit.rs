//! Rate-limiting primitives.
//!
//! The [`RateLimiter`] trait abstracts the backend so a host can run with
//! the bundled in-memory limiter, swap in a Redis-backed implementation,
//! or use [`NoopRateLimiter`] to disable enforcement entirely. The
//! framework-agnostic managers in this crate (notably
//! [`SignupManager`](crate::signup::SignupManager)) consult a limiter on
//! sensitive operations and surface [`Error::RateLimited`] when the
//! configured budget is exhausted.

use std::borrow::Cow;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::error::{Error, Result, StorageResult};

/// A structured, multi-dimensional rate-limit key.
///
/// Layered limits — per-IP, per-account, per-credential — name their
/// dimensions rather than smuggling them into a flat string a backend
/// cannot decompose. The `operation` names the limited action (e.g.
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

    /// Stable single-string rendering for backends that key on one string,
    /// such as the bundled
    /// [`InMemoryRateLimiter`](crate::memory::InMemoryRateLimiter): the
    /// operation followed by each `|name=value` in order. Such a backend uses
    /// this string as the bucket identity, so the mapping must be
    /// collision-free — two keys produce the same string only when they share
    /// the same operation and the same ordered dimensions. Distinct axes (a
    /// per-IP limit versus a per-account limit, say) therefore never charge
    /// into the same bucket.
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

/// What a [`RateLimiter::check_and_charge`] call decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// Within budget; the attempt was charged and the caller may proceed.
    Allowed,
    /// Budget exhausted; the caller must wait at least `retry_after`
    /// before another attempt is likely to succeed.
    Limited {
        /// How long the caller should wait before retrying.
        retry_after: Duration,
    },
}

impl RateLimitDecision {
    /// `true` when the decision is [`Allowed`](Self::Allowed).
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// A "no more than `max_attempts` events per `window`" rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitPolicy {
    /// Maximum number of charged attempts permitted within `window`.
    pub max_attempts: u32,
    /// Rolling window the `max_attempts` budget applies over.
    pub window: Duration,
}

impl RateLimitPolicy {
    /// Build a policy of `max_attempts` per `window`.
    pub const fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            max_attempts,
            window,
        }
    }
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
    ///
    /// The [`RateLimitKey`] is structured (operation + named dimensions); a
    /// single-string backend flattens it with
    /// [`RateLimitKey::canonical`].
    async fn check_and_charge(
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
    async fn check_and_charge(
        &self,
        _key: &RateLimitKey,
        _policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        Ok(RateLimitDecision::Allowed)
    }
}

/// Enforce one rate-limit policy for an `operation` scoped to a single
/// `(dimension, value)` axis. A `None` policy or a `None` value is a no-op
/// (the policy is disabled or there is no value to key on — e.g. an absent
/// client IP). The structured [`RateLimitKey`] names the dimension rather
/// than concatenating it into the operation string, so a backend can layer
/// independent counters per axis.
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

/// Enforce a list of rate-limit policies in order, short-circuiting on the
/// first rejection. Each entry is `(policy, operation, dimension, value)`
/// with the same semantics as [`enforce_rate_limit`]. `on_reject` runs once,
/// just before the rejecting error is returned — recovery uses it to emit a
/// `RateLimited` audit event; signup passes a no-op.
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
}
