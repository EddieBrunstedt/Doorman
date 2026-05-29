//! Storage-adapter bench: the cost of the SQLx + SQLite session adapter,
//! to compare against the in-memory reference baseline (`bauth-core`'s
//! `session` bench).
//!
//! - `create` — insert a fresh session row.
//! - `find_by_token_hash` — the per-request hot path the session layer
//!   runs on every authenticated request.
//! - `find_by_id` — the indexed primary-key lookup.
//!
//! Runs against an ephemeral `sqlite::memory:` database. Requires the
//! `sqlite` feature:
//!
//! ```sh
//! cargo bench -p bauth-sqlx --features sqlite --bench storage
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bauth_core::session::hash_token;
use bauth_core::storage::{Session, SessionId, SessionStore, User, UserId};
use bauth_sqlx::SqliteStorage;
use chrono::Utc;
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

struct Scaffold {
    sessions: std::sync::Arc<dyn SessionStore>,
    user_id: UserId,
    seeded_token_hash: bauth_core::storage::TokenHash,
    seeded_id: SessionId,
}

async fn build_scaffold() -> Scaffold {
    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let users = storage.user_store();
    let sessions = storage.session_store();

    let now = Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    users.create_user(user).await.expect("create user");

    // One seeded session for the read benches.
    let seeded_token_hash = hash_token("seeded-token");
    let seeded_id = SessionId::new();
    sessions
        .create_session(make_session(seeded_id, user_id, seeded_token_hash, now))
        .await
        .expect("seed session");

    Scaffold {
        sessions,
        user_id,
        seeded_token_hash,
        seeded_id,
    }
}

fn make_session(
    id: SessionId,
    user_id: UserId,
    token_hash: bauth_core::storage::TokenHash,
    now: chrono::DateTime<Utc>,
) -> Session {
    Session {
        id,
        user_id,
        token_hash,
        created_at: now,
        expires_at: now + chrono::Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    }
}

fn storage(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());
    let now = Utc::now();
    let counter = AtomicU64::new(0);

    c.bench_function("sqlite_session_create", |b| {
        b.to_async(&runtime).iter(|| async {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let session = make_session(
                SessionId::new(),
                scaffold.user_id,
                hash_token(&format!("create-{n}")),
                now,
            );
            scaffold
                .sessions
                .create_session(session)
                .await
                .expect("create session");
        });
    });

    c.bench_function("sqlite_find_by_token_hash", |b| {
        b.to_async(&runtime).iter(|| async {
            scaffold
                .sessions
                .find_session_by_token_hash(&scaffold.seeded_token_hash)
                .await
                .expect("find by token hash")
                .expect("session exists");
        });
    });

    c.bench_function("sqlite_find_by_id", |b| {
        b.to_async(&runtime).iter(|| async {
            scaffold
                .sessions
                .find_session_by_id(scaffold.seeded_id)
                .await
                .expect("find by id")
                .expect("session exists");
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = storage
}
criterion_main!(benches);
