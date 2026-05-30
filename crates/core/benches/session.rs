//! Session-manager benches: the steady-state cost a host pays on every
//! authenticated request, isolated from any HTTP layer or cache.
//!
//! - `create` — `SessionManager::create` against the in-memory store
//!   (token gen + hash + store insert + audit emit).
//! - `validate` — manager-level `validate` against the in-memory store
//!   (the axum `session_cache` bench isolates the cache, and `request_path`
//!   measures the full layer/router path; this measures the manager
//!   underneath them).
//! - `token_hash` — `hash_token` throughput. It runs on every
//!   authenticated request, so it is worth a standalone baseline.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-core --bench session
//! ```

use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::memory::InMemorySessionStore;
use bauth_core::session::{SessionConfig, SessionContext, SessionManager, hash_token};
use bauth_core::storage::{SessionStore, UserId};
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

fn session_manager() -> SessionManager {
    SessionManager::new(
        Arc::new(InMemorySessionStore::new()) as Arc<dyn SessionStore>,
        Arc::new(SystemClock) as Arc<dyn Clock>,
        Arc::new(NoopAuditSink) as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    )
}

fn session(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let user_id = UserId::new();

    let manager = session_manager();
    c.bench_function("session_create", |b| {
        b.to_async(&runtime).iter(|| async {
            manager
                .create(user_id, SessionContext::default())
                .await
                .expect("create session");
        });
    });

    // Seed one session, then measure the lookup-and-validate path against
    // the store with no cache in front of it.
    let manager = session_manager();
    let token = runtime.block_on(async {
        manager
            .create(user_id, SessionContext::default())
            .await
            .expect("seed session")
            .token
    });
    c.bench_function("session_validate", |b| {
        b.to_async(&runtime).iter(|| async {
            manager.validate(&token).await.expect("validate");
        });
    });

    c.bench_function("token_hash", |b| {
        b.iter(|| hash_token(std::hint::black_box(&token)));
    });
}

criterion_group!(benches, session);
criterion_main!(benches);
