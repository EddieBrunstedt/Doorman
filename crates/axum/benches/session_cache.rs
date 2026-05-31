//! Session-cache microbenchmarks for the real `bauth-axum` request cache.
//!
//! These benches intentionally do **not** drive the full `SessionLayer` or
//! router. They isolate the cache component that the layer uses on real
//! requests:
//!
//! - `cache_hit` — raw `SessionCache::get` hit with a precomputed token
//!   hash. This is the lower bound for a warm session-resolution cache.
//! - `cache_miss_populate` — the cold-cache populate path after token
//!   extraction: hash the token, observe a cache miss, validate through
//!   `SessionManager`, fetch the user, and insert the resolved auth context
//!   into the cache. The cache clear happens in untimed setup.
//!
//! For the authoritative full request path, including token extraction,
//! middleware, router dispatch, extension insertion, and handler work, see
//! `request_path.rs`.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-axum --bench session_cache
//! ```

use std::sync::Arc;
use std::time::Duration;

use bauth_axum::{SessionCache, SessionCacheConfig};
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::memory::{InMemorySessionStore, InMemoryUserStore};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager, hash_token};
use bauth_core::storage::{SessionStore, User, UserId, UserStore};
use chrono::Utc;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

struct Scaffold {
    session_manager: SessionManager,
    user_store: Arc<dyn UserStore>,
    cache: SessionCache,
    token: String,
    user_id: UserId,
}

async fn build_scaffold() -> Scaffold {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
    let session_store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let user_store_impl: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let user_store: Arc<dyn UserStore> = user_store_impl.clone();

    let session_manager = SessionManager::new(
        session_store,
        clock,
        audit,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );

    let now = Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("u@example.com".into()),
        email_verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    user_store_impl
        .create_user(user.clone())
        .await
        .expect("seed user");

    let issued = session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session");

    Scaffold {
        session_manager,
        user_store,
        cache: SessionCache::new(SessionCacheConfig::default()),
        token: issued.token,
        user_id: user.id,
    }
}

fn session_cache(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());

    let mut group = c.benchmark_group("session_cache");

    // Seed once, then measure the raw in-process cache hit. The token hash
    // is precomputed deliberately: this function answers "how expensive is
    // the LRU lookup + clone?" rather than "how expensive is the whole
    // session layer?".
    let token_hash = hash_token(&scaffold.token);
    runtime.block_on(async {
        let session = scaffold
            .session_manager
            .validate(&scaffold.token)
            .await
            .expect("seed validate");
        let user = scaffold
            .user_store
            .find_user_by_id(session.user_id)
            .await
            .expect("seed user lookup")
            .expect("user exists");
        scaffold
            .cache
            .insert(token_hash, Arc::new(session), Arc::new(user));
    });
    group.bench_function("cache_hit", |b| {
        b.iter(|| {
            let cached = scaffold
                .cache
                .get(std::hint::black_box(&token_hash))
                .expect("cache hit");
            std::hint::black_box(cached);
        });
    });

    // Clear the cache outside the timed section for each measured iteration.
    // The timed body mirrors the layer's cold-cache populate sequence after
    // token extraction: hash -> miss -> validate -> user lookup -> insert.
    group.bench_function("cache_miss_populate", |b| {
        b.to_async(&runtime).iter_batched(
            || {
                scaffold.cache.invalidate_user(scaffold.user_id);
            },
            |_| async {
                let token_hash = hash_token(std::hint::black_box(&scaffold.token));
                assert!(scaffold.cache.get(&token_hash).is_none(), "cache miss");
                let session = scaffold
                    .session_manager
                    .validate(&scaffold.token)
                    .await
                    .expect("validate");
                let user = scaffold
                    .user_store
                    .find_user_by_id(session.user_id)
                    .await
                    .expect("user lookup")
                    .expect("user exists");
                scaffold
                    .cache
                    .insert(token_hash, Arc::new(session), Arc::new(user));
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

criterion_group!(benches, session_cache);
criterion_main!(benches);
