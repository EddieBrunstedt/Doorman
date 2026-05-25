//! Session-validation bench: cached vs uncached path.
//!
//! The session layer falls into two regimes for an authenticated request:
//!
//! - **Uncached** — the cache misses, so the layer hits
//!   `SessionStore::find_session_by_token_hash` and
//!   `UserStore::find_user_by_id` on the host's storage.
//! - **Cached** — a previous request seeded the cache, so the layer
//!   returns immediately from a process-local `LruCache` lookup.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-axum --bench session_validate
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
use criterion::{Criterion, criterion_group, criterion_main};
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

    let user = User {
        id: UserId::new(),
        email: Some("u@example.com".into()),
        email_verified_at: Some(Utc::now()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
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

fn session_validate(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());

    let mut group = c.benchmark_group("session_validate");

    // Uncached path: clear the cache before each iteration to force the
    // full `SessionStore::find_session_by_token_hash` +
    // `UserStore::find_user_by_id` round-trip the layer would run.
    group.bench_function("uncached", |b| {
        b.to_async(&runtime).iter(|| async {
            scaffold.cache.invalidate_user(scaffold.user_id);
            let token_hash = hash_token(&scaffold.token);
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
            scaffold.cache.insert(token_hash, session, user);
        });
    });

    // Cached path: seed once, then measure the in-process cache hit. This
    // is the steady-state cost for any handler that runs after a request
    // has warmed the cache.
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
        scaffold.cache.insert(token_hash, session, user);
    });
    group.bench_function("cached", |b| {
        b.to_async(&runtime).iter(|| async {
            let _ = scaffold.cache.get(&token_hash).expect("cache hit");
        });
    });

    group.finish();
}

criterion_group!(benches, session_validate);
criterion_main!(benches);
