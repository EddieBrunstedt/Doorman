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
