mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use doorman_core::memory::InMemoryStorage;
use doorman_core::session::{SessionContext, SessionManager, hash_token};
use doorman_core::storage::{User, UserId, UserStatus};
use tokio::runtime::Runtime;

fn session_manager(runtime: &Runtime, user_id: UserId) -> SessionManager {
    let storage = InMemoryStorage::new().all_stores();
    let now = chrono::Utc::now();
    runtime
        .block_on(storage.users.create_user(User {
            id: user_id,
            email: Some("bench@example.com".to_owned()),
            email_verified_at: Some(now),
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        }))
        .expect("seed user");
    support::in_memory_core(storage).session_manager
}

fn session(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let user_id = UserId::new();

    let manager = session_manager(&runtime, user_id);
    c.bench_function("session_create", |b| {
        b.to_async(&runtime).iter(|| async {
            manager
                .create(user_id, SessionContext::default())
                .await
                .expect("create session");
        });
    });

    let manager = session_manager(&runtime, user_id);
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
