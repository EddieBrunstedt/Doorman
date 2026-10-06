mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use doorman_core::memory::InMemoryStorage;
use doorman_core::session::SessionContext;
use doorman_core::signup::SignupManager;
use tokio::runtime::Runtime;

fn signup_manager() -> SignupManager {
    support::in_memory_core(InMemoryStorage::new().all_stores()).signup
}

fn enrollment(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    c.bench_function("signup_request", |b| {
        b.to_async(&runtime).iter_batched(
            signup_manager,
            |manager| async move {
                manager
                    .request_signup("user@example.com", None, SessionContext::default())
                    .await
                    .expect("request signup");
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, enrollment);
criterion_main!(benches);
