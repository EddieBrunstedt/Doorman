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
//! cargo bench -p doorman-core --bench session
//! ```

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use doorman_core::session::{SessionContext, SessionManager, hash_token};
use doorman_core::storage::UserId;
use tokio::runtime::Runtime;

fn session_manager() -> SessionManager {
    support::in_memory_core().session_manager
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
