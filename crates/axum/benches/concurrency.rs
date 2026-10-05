//! Contended session-resolution benches.
//!
//! The single-threaded `session_cache` and `request_path` benches measure
//! latency on an uncontended structure. These benches instead put a fixed
//! fan-out of concurrent work through the two shared structures on the
//! resolution hot path, to characterize their behaviour under load:
//!
//! - `cache_hit` — `CONCURRENCY` concurrent `SessionCache::get` hits across
//!   distinct token hashes, exercising the cache's internal locking.
//! - `validate` — `CONCURRENCY` concurrent `SessionManager::validate_by_hash`
//!   calls against the in-memory session store with no cache in front,
//!   exercising the reference store's read locking.
//!
//! Each measured iteration spawns `CONCURRENCY` tasks onto a fixed-size
//! multi-threaded runtime and joins them, so the number reflects per-batch
//! latency; throughput is reported per resolved request.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-axum --bench concurrency
//! ```

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use doorman_axum::{SessionCache, SessionCacheConfig};
use doorman_core::audit::{AuditSink, NoopAuditSink};
use doorman_core::clock::{Clock, SystemClock};
use doorman_core::memory::{InMemorySessionStore, InMemoryUserStore};
use doorman_core::session::{SessionConfig, SessionContext, SessionManager, hash_token};
use doorman_core::storage::{AccountStatus, SessionStore, TokenHash, User, UserId, UserStore};
use tokio::runtime::Builder;
use tokio::task::JoinSet;

/// Concurrent resolutions issued per measured iteration.
const CONCURRENCY: usize = 32;
/// Distinct live sessions seeded, so concurrent work hits many keys rather
/// than serializing on one.
const POOL: usize = 1_024;
/// Fixed worker count so contention is reproducible across machines with
/// different core counts.
const WORKERS: usize = 4;

struct Scaffold {
    session_manager: SessionManager,
    cache: SessionCache,
    token_hashes: Arc<Vec<TokenHash>>,
}

async fn build_scaffold() -> Scaffold {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let session_store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let user_store_impl: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());

    let session_manager = SessionManager::new(
        session_store,
        clock.clone(),
        audit,
        SessionConfig {
            absolute_lifetime: Duration::from_secs(60 * 60),
            ..SessionConfig::default()
        },
    );

    // Capacity well above POOL so every seeded session stays resident across
    // all shards — the hit bench must never observe an eviction miss. (Shards
    // are keyed on the token-hash prefix, so the per-shard load is uneven; the
    // generous headroom absorbs that skew.)
    let cache = SessionCache::new(
        SessionCacheConfig {
            capacity: NonZeroUsize::new(POOL * 16).expect("non-zero capacity"),
            ..SessionCacheConfig::default()
        },
        clock,
    );

    let now = Utc::now();
    let mut token_hashes = Vec::with_capacity(POOL);
    for n in 0..POOL {
        let user = User {
            id: UserId::new(),
            email: Some(format!("u{n}@example.com")),
            email_verified_at: Some(now),
            status: AccountStatus::Active,
            created_at: now,
            updated_at: now,
        };
        let user_id = user.id;
        user_store_impl
            .create_user(user.clone())
            .await
            .expect("seed user");
        let issued = session_manager
            .create(user_id, SessionContext::default())
            .await
            .expect("create session");
        let hash = hash_token(&issued.token);
        let session = session_manager
            .validate_by_hash(&hash)
            .await
            .expect("seed validate");
        cache.insert(hash, Arc::new(session), Arc::new(user));
        token_hashes.push(hash);
    }

    Scaffold {
        session_manager,
        cache,
        token_hashes: Arc::new(token_hashes),
    }
}

fn concurrency(c: &mut Criterion) {
    let runtime = Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .build()
        .expect("multi-thread runtime");
    let scaffold = runtime.block_on(build_scaffold());

    let mut group = c.benchmark_group("concurrency");
    group.throughput(Throughput::Elements(CONCURRENCY as u64));

    group.bench_function("cache_hit", |b| {
        b.to_async(&runtime).iter(|| {
            let cache = scaffold.cache.clone();
            let hashes = scaffold.token_hashes.clone();
            async move {
                let mut set = JoinSet::new();
                for i in 0..CONCURRENCY {
                    let cache = cache.clone();
                    let hash = hashes[i % hashes.len()];
                    set.spawn(async move {
                        let cached = cache.get(&hash).expect("cache hit");
                        std::hint::black_box(cached);
                    });
                }
                while let Some(joined) = set.join_next().await {
                    joined.expect("task panicked");
                }
            }
        });
    });

    group.bench_function("validate", |b| {
        b.to_async(&runtime).iter(|| {
            let manager = scaffold.session_manager.clone();
            let hashes = scaffold.token_hashes.clone();
            async move {
                let mut set = JoinSet::new();
                for i in 0..CONCURRENCY {
                    let manager = manager.clone();
                    let hash = hashes[i % hashes.len()];
                    set.spawn(async move {
                        let session = manager.validate_by_hash(&hash).await.expect("validate");
                        std::hint::black_box(session);
                    });
                }
                while let Some(joined) = set.join_next().await {
                    joined.expect("task panicked");
                }
            }
        });
    });

    group.finish();
}

criterion_group!(benches, concurrency);
criterion_main!(benches);
