use std::time::Duration;

use async_trait::async_trait;
use doorman_core::clock::Clock;
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use std::sync::Arc;
use uuid::Uuid;

use crate::client::RedisClient;
use crate::scripts;

pub(crate) struct RedisRateLimiter {
    client: RedisClient,
    clock: Arc<dyn Clock>,
    script: redis::Script,
}

impl RedisRateLimiter {
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
            let retry_after = Duration::from_millis(retry_after_ms.max(0) as u64);
            Ok(RateLimitDecision::Limited { retry_after })
        }
    }
}
