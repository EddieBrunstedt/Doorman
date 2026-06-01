//! Rate-limiter bench: the per-check cost the signup / recovery request
//! paths pay before doing any real work.
//!
//! Two regimes: `allowed` charges an attempt that stays within budget,
//! `limited` measures a check that has already exhausted its budget and
//! returns `Limited` (the hot path under an active attack).
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-core --bench rate_limit
//! ```

use std::sync::Arc;
use std::time::Duration;

use bauth_core::clock::{Clock, SystemClock};
use bauth_core::memory::InMemoryRateLimiter;
use bauth_core::rate_limit::{RateLimitKey, RateLimitPolicy, RateLimiter};
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

fn rate_limit(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    // A window shorter than the gap between iterations so each check finds a
    // near-empty bucket (prior attempts have aged out), keeping the
    // measurement representative of steady allowed traffic rather than the
    // O(n) cost of an ever-growing bucket. `max_attempts` is high so the
    // check always lands in the allowed branch.
    let allowed_policy = RateLimitPolicy::new(u32::MAX, Duration::from_nanos(1));
    let limiter = InMemoryRateLimiter::new(Arc::new(SystemClock) as Arc<dyn Clock>);
    let allowed_key = RateLimitKey::new("rate_limit").with("ip", "203.0.113.7");
    c.bench_function("rate_limit_allowed", |b| {
        b.to_async(&runtime).iter(|| async {
            limiter
                .check(&allowed_key, allowed_policy)
                .await
                .expect("check");
        });
    });

    let limited_policy = RateLimitPolicy::new(1, Duration::from_secs(60));
    let limiter = InMemoryRateLimiter::new(Arc::new(SystemClock) as Arc<dyn Clock>);
    let limited_key = RateLimitKey::new("rate_limit").with("ip", "203.0.113.9");
    runtime.block_on(async {
        limiter
            .check(&limited_key, limited_policy)
            .await
            .expect("seed attempt");
    });
    c.bench_function("rate_limit_limited", |b| {
        b.to_async(&runtime).iter(|| async {
            limiter
                .check(&limited_key, limited_policy)
                .await
                .expect("check");
        });
    });
}

criterion_group!(benches, rate_limit);
criterion_main!(benches);
