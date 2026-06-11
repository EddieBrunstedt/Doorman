//! Behaviour tests for the Redis-backed [`RedisRateLimiter`].
//!
//! These port the in-memory limiter's contract as the spec (§6): charge up to
//! budget, reject past it, `retry_after` shape, window rollover, key isolation,
//! and single-script atomicity under concurrency. A mock clock makes the
//! window-rollover assertions deterministic without sleeping.
//!
//! The full suite runs against both Redis and Valkey (gated on `REDIS_URL` /
//! `VALKEY_URL`) so any Lua/sorted-set drift between the two servers is caught
//! mechanically. Skipped with a message when the relevant URL is unset.

use std::sync::Arc;
use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use doorman_core::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use doorman_redis::RedisStorage;
use doorman_test_support::MockClock;
use uuid::Uuid;

/// Build a limiter with a mock clock against `url_var`, or `None` (with a skip
/// message) when it is unset. A unique key prefix isolates each run.
async fn limiter(url_var: &str) -> Option<(Arc<dyn RateLimiter>, Arc<MockClock>)> {
    let url = match std::env::var(url_var) {
        Ok(url) => url,
        Err(_) => {
            eprintln!("{url_var} not set; skipping rate-limit suite");
            return None;
        }
    };
    let clock = Arc::new(MockClock::new(Utc::now()));
    let redis = RedisStorage::connect(&url)
        .await
        .expect("connect to redis/valkey")
        .with_prefix(format!("doorman-test:{}:", Uuid::new_v4()));
    let limiter = redis.rate_limiter_with_clock(clock.clone());
    Some((limiter, clock))
}

/// A fresh key on a distinct operation so each sub-check starts from an empty
/// bucket regardless of clock position.
fn fresh_key(op: &'static str) -> RateLimitKey {
    RateLimitKey::new(op).with("id", Uuid::new_v4().to_string())
}

async fn charge(
    limiter: &Arc<dyn RateLimiter>,
    key: &RateLimitKey,
    policy: RateLimitPolicy,
) -> RateLimitDecision {
    limiter
        .check_and_charge(key, policy)
        .await
        .expect("check_and_charge")
}

/// The complete behaviour suite, run against one server.
async fn run_suite(url_var: &str) {
    let Some((limiter, clock)) = limiter(url_var).await else {
        return;
    };

    charges_up_to_budget_then_rejects(&limiter, &clock).await;
    window_rollover_refills_budget(&limiter, &clock).await;
    distinct_keys_have_independent_budgets(&limiter).await;
    zero_budget_always_limits(&limiter).await;
}

/// The first `max_attempts` charges are allowed; the next is limited, and its
/// `retry_after` reflects the oldest live attempt's age within the window.
async fn charges_up_to_budget_then_rejects(limiter: &Arc<dyn RateLimiter>, clock: &MockClock) {
    let policy = RateLimitPolicy::new(3, Duration::from_secs(60));
    let key = fresh_key("ratelimit/budget");

    for i in 0..3 {
        assert_eq!(
            charge(limiter, &key, policy).await,
            RateLimitDecision::Allowed,
            "attempt {i} is within the budget of 3",
        );
    }

    // Fourth attempt at the same instant: limited, and a full window must pass
    // before the oldest of the three frees a slot.
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Limited {
            retry_after: Duration::from_secs(60),
        },
        "the fourth attempt is rejected for a full window",
    );

    // Halfway through the window the wait shrinks accordingly; a rejected
    // attempt must not itself be charged (it does not reset the window).
    clock.advance(ChronoDuration::seconds(30));
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Limited {
            retry_after: Duration::from_secs(30),
        },
        "retry_after counts down as the oldest attempt ages",
    );
}

/// Once the window has fully elapsed past the original charges, the oldest
/// entries age out and the budget refills.
async fn window_rollover_refills_budget(limiter: &Arc<dyn RateLimiter>, clock: &MockClock) {
    let policy = RateLimitPolicy::new(2, Duration::from_secs(60));
    let key = fresh_key("ratelimit/rollover");

    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Allowed
    );
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Allowed
    );
    assert!(
        matches!(
            charge(limiter, &key, policy).await,
            RateLimitDecision::Limited { .. }
        ),
        "third attempt exhausts the budget of 2",
    );

    // Step just past the window so both prior attempts age out.
    clock.advance(ChronoDuration::seconds(61));
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Allowed,
        "the budget refills once the window rolls over",
    );
}

/// Distinct keys (different dimensions) never share a bucket.
async fn distinct_keys_have_independent_budgets(limiter: &Arc<dyn RateLimiter>) {
    let policy = RateLimitPolicy::new(1, Duration::from_secs(60));
    let key_a = fresh_key("ratelimit/isolation");
    let key_b = fresh_key("ratelimit/isolation");

    assert_eq!(
        charge(limiter, &key_a, policy).await,
        RateLimitDecision::Allowed
    );
    assert_eq!(
        charge(limiter, &key_b, policy).await,
        RateLimitDecision::Allowed,
        "key_b has its own budget, unaffected by key_a",
    );
    assert!(
        matches!(
            charge(limiter, &key_a, policy).await,
            RateLimitDecision::Limited { .. }
        ),
        "key_a is now at its budget",
    );
}

/// A `max_attempts` of zero rejects every attempt, asking the caller to wait a
/// full window (matching the in-memory limiter).
async fn zero_budget_always_limits(limiter: &Arc<dyn RateLimiter>) {
    let policy = RateLimitPolicy::new(0, Duration::from_secs(60));
    let key = fresh_key("ratelimit/zero");

    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Limited {
            retry_after: Duration::from_secs(60),
        },
    );
}

#[tokio::test]
#[ignore = "pending testcontainers migration; see crates/sqlx/tests/postgres.rs"]
async fn rate_limit_redis() {
    run_suite("REDIS_URL").await;
}

#[tokio::test]
#[ignore = "pending testcontainers migration; see crates/sqlx/tests/postgres.rs"]
async fn rate_limit_valkey() {
    run_suite("VALKEY_URL").await;
}

/// Under concurrent load against one key, the single-script check-and-charge
/// admits exactly `max_attempts` callers — proof the evict/count/charge
/// sequence is atomic across racing connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "pending testcontainers migration; see crates/sqlx/tests/postgres.rs"]
async fn concurrent_charges_admit_exactly_the_budget() {
    let Some((limiter, _clock)) = limiter("REDIS_URL").await else {
        return;
    };
    const RACERS: usize = 64;
    const BUDGET: u32 = 10;
    let policy = RateLimitPolicy::new(BUDGET, Duration::from_secs(60));
    let key = fresh_key("ratelimit/concurrent");

    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let limiter = limiter.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            charge(&limiter, &key, policy).await.is_allowed()
        }));
    }

    let mut allowed = 0;
    for handle in handles {
        if handle.await.expect("join") {
            allowed += 1;
        }
    }
    assert_eq!(
        allowed, BUDGET as usize,
        "exactly the budget is admitted under concurrency",
    );
}
