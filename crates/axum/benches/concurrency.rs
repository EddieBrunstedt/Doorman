mod support;

use std::num::NonZeroUsize;
use std::sync::Arc;

use chrono::Utc;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use doorman_axum::{SessionCache, SessionCacheConfig};
use doorman_core::session::{SessionContext, SessionManager, hash_token};
use doorman_core::storage::{AccountStatus, TokenHash, User, UserId};
use tokio::runtime::Builder;
use tokio::task::JoinSet;

const CONCURRENCY: usize = 32;
const POOL: usize = 1_024;
const WORKERS: usize = 4;

struct Scaffold {
    session_manager: SessionManager,
    cache: SessionCache,
    token_hashes: Arc<Vec<TokenHash>>,
}

async fn build_scaffold() -> Scaffold {
    let core = support::in_memory_core(SessionCacheConfig {
        capacity: NonZeroUsize::new(POOL * 16).expect("non-zero capacity"),
        ..SessionCacheConfig::default()
    });

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
        core.storage
            .users
            .create_user(user)
            .await
            .expect("seed user");
        let issued = core
            .session_manager
            .create(user_id, SessionContext::default())
            .await
            .expect("create session");
        core.resolver
            .resolve(&issued.token)
            .await
            .expect("seed resolve");
        token_hashes.push(hash_token(&issued.token));
    }

    Scaffold {
        session_manager: core.session_manager,
        cache: core.resolver.cache().clone(),
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
