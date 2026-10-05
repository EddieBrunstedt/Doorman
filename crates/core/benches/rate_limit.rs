use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::memory::InMemoryRateLimiter;
use doorman_core::rate_limit::{RateLimitKey, RateLimitPolicy, RateLimiter};
use tokio::runtime::Runtime;

fn rate_limit(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    let allowed_policy = RateLimitPolicy::new(u32::MAX, Duration::from_nanos(1));
    let limiter = InMemoryRateLimiter::new(Arc::new(SystemClock) as Arc<dyn Clock>);
    let allowed_key = RateLimitKey::new("rate_limit").with("ip", "203.0.113.7");
    c.bench_function("rate_limit_allowed", |b| {
        b.to_async(&runtime).iter(|| async {
            limiter
                .check_and_charge(&allowed_key, allowed_policy)
                .await
                .expect("check");
        });
    });

    let limited_policy = RateLimitPolicy::new(1, Duration::from_secs(60));
    let limiter = InMemoryRateLimiter::new(Arc::new(SystemClock) as Arc<dyn Clock>);
    let limited_key = RateLimitKey::new("rate_limit").with("ip", "203.0.113.9");
    runtime.block_on(async {
        limiter
            .check_and_charge(&limited_key, limited_policy)
            .await
            .expect("seed attempt");
    });
    c.bench_function("rate_limit_limited", |b| {
        b.to_async(&runtime).iter(|| async {
            limiter
                .check_and_charge(&limited_key, limited_policy)
                .await
                .expect("check");
        });
    });
}

criterion_group!(benches, rate_limit);
criterion_main!(benches);
