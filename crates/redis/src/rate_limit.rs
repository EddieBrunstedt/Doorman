//! Redis-backed [`RateLimiter`].
//!
//! A shared, cross-replica rate limiter built on a sliding-window log: each
//! `(key, window)` bucket is a sorted set of recent attempt timestamps, and
//! every check-and-charge runs the evict/count/charge sequence as one Lua
//! script ([`scripts::SLIDING_WINDOW`](crate::scripts::SLIDING_WINDOW)) so the
//! decision is atomic even when many replicas charge the same key at once. The
//! semantics match the bundled
//! [`InMemoryRateLimiter`](doorman_core::memory::InMemoryRateLimiter); swapping
//! one for the other does not change the limits a caller observes.
//!
//! `now` comes from an injected [`Clock`], like the in-memory limiter, rather
//! than the server clock — this keeps behaviour deterministic under a mock
//! clock and matches the rest of doorman's time handling. It assumes the
//! application replicas keep roughly synchronised clocks (NTP); the rolling
//! window (typically minutes to hours for auth limits) dwarfs ordinary skew.

use std::time::Duration;

use async_trait::async_trait;
use doorman_core::clock::Clock;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use std::sync::Arc;
use uuid::Uuid;

use crate::client::RedisClient;
use crate::scripts;

/// Rate limiter backed by a Redis/Valkey sorted-set sliding-window log.
pub(crate) struct RedisRateLimiter {
    client: RedisClient,
    clock: Arc<dyn Clock>,
    script: redis::Script,
}

impl RedisRateLimiter {
    /// Build a limiter over `client`, sourcing `now` from `clock`. The Lua
    /// script is compiled once here and thereafter invoked via `EVALSHA`.
    pub(crate) fn new(client: RedisClient, clock: Arc<dyn Clock>) -> Self {
        Self {
            client,
            clock,
            script: redis::Script::new(scripts::SLIDING_WINDOW),
        }
    }
}

#[async_trait]
impl RateLimiter for RedisRateLimiter {
    async fn check_and_charge(
        &self,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
    ) -> StorageResult<RateLimitDecision> {
        let now_ms = self.clock.now().timestamp_millis();
        let window_ms_u128 = policy.window.as_millis();
        let window_ms = i64::try_from(window_ms_u128)
            .map_err(|_| StorageError::msg("rate limit window overflows i64 milliseconds"))?;
        let bucket = self
            .client
            .keys()
            .rate_limit(&key.canonical(), window_ms_u128);
        // A unique member per attempt: two attempts in the same millisecond stay
        // two distinct log entries rather than collapsing into one.
        let member = Uuid::new_v4().to_string();

        let mut conn = self.client.conn();
        let mut invocation = self.script.prepare_invoke();
        invocation
            .key(&bucket)
            .arg(now_ms)
            .arg(window_ms)
            .arg(policy.max_attempts)
            .arg(member);
        let (decision, retry_after_ms): (i64, i64) = invocation
            .invoke_async(&mut conn)
            .await
            .map_err(StorageError::new)?;

        if decision == 1 {
            Ok(RateLimitDecision::Allowed)
        } else {
            // `retry_after_ms` is non-negative by construction in the script.
            let retry_after = Duration::from_millis(retry_after_ms.max(0) as u64);
            Ok(RateLimitDecision::Limited { retry_after })
        }
    }
}
