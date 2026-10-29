use crate::common;

use std::sync::Arc;
use std::time::Duration;

use crate::common::{Backend, ContainerGuard};
use chrono::{Duration as ChronoDuration, Utc};
use doorman_core::rate_limit::{RateLimitDecision, RateLimitKey, RateLimitPolicy, RateLimiter};
use doorman_test_support::MockClock;
use uuid::Uuid;

async fn limiter(backend: Backend) -> (ContainerGuard, Arc<dyn RateLimiter>, Arc<MockClock>) {
    let (guard, server) = common::start(backend).await;
    let clock = Arc::new(MockClock::new(Utc::now()));
    let limiter = server
        .confined_storage(&common::namespace())
        .await
        .rate_limiter_with_clock(clock.clone());
    (guard, limiter, clock)
}

fn fresh_key(op: &'static str) -> RateLimitKey {
    RateLimitKey::new(format!("{op}:{}", Uuid::new_v4()))
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

async fn run_suite(backend: Backend) {
    let (_node, limiter, clock) = limiter(backend).await;

    charges_up_to_budget_then_rejects(&limiter, &clock).await;
    window_rollover_refills_budget(&limiter, &clock).await;
    distinct_keys_have_independent_budgets(&limiter).await;
    zero_budget_always_limits(&limiter).await;
}

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

    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Limited {
            retry_after: Duration::from_secs(60),
        },
        "the fourth attempt is rejected for a full window",
    );

    clock.advance(ChronoDuration::seconds(30));
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Limited {
            retry_after: Duration::from_secs(30),
        },
        "retry_after counts down as the oldest attempt ages",
    );
}

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

    clock.advance(ChronoDuration::seconds(61));
    assert_eq!(
        charge(limiter, &key, policy).await,
        RateLimitDecision::Allowed,
        "the budget refills once the window rolls over",
    );
}

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
async fn rate_limit_redis() {
    run_suite(Backend::Redis).await;
}

#[tokio::test]
async fn rate_limit_valkey() {
    run_suite(Backend::Valkey).await;
}

#[tokio::test]
async fn rate_limit_redis_cluster() {
    run_suite(Backend::RedisCluster).await;
}

#[tokio::test]
async fn rate_limit_valkey_cluster() {
    run_suite(Backend::ValkeyCluster).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_charges_admit_exactly_the_budget() {
    let (_node, limiter, _clock) = limiter(Backend::Redis).await;
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
