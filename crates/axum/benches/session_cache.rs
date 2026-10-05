mod support;

use chrono::Utc;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use doorman_axum::SessionCacheConfig;
use doorman_core::resolve::SessionResolver;
use doorman_core::session::{SessionContext, hash_token};
use doorman_core::storage::{AccountStatus, User, UserId};
use tokio::runtime::Runtime;

struct Scaffold {
    resolver: SessionResolver,
    token: String,
    user_id: UserId,
}

async fn build_scaffold() -> Scaffold {
    let core = support::in_memory_core(SessionCacheConfig::default());

    let now = Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("u@example.com".into()),
        email_verified_at: Some(now),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    core.storage
        .users
        .create_user(user.clone())
        .await
        .expect("seed user");

    let issued = core
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session");

    Scaffold {
        resolver: core.resolver,
        token: issued.token,
        user_id: user.id,
    }
}

fn session_cache(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());
    let cache = scaffold.resolver.cache();

    let mut group = c.benchmark_group("session_cache");

    let token_hash = hash_token(&scaffold.token);
    runtime.block_on(async {
        scaffold
            .resolver
            .resolve(&scaffold.token)
            .await
            .expect("seed resolve");
    });
    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            let cached = cache
                .get(std::hint::black_box(&token_hash))
                .expect("cache hit");
            std::hint::black_box(cached);
        });
    });

    group.bench_function("cache_miss_populate", |b| {
        b.to_async(&runtime).iter_batched(
            || {
                cache.invalidate_user(scaffold.user_id);
            },
            |_| async {
                let resolved = scaffold
                    .resolver
                    .resolve(std::hint::black_box(&scaffold.token))
                    .await
                    .expect("resolve");
                std::hint::black_box(resolved);
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(benches, session_cache);
criterion_main!(benches);
