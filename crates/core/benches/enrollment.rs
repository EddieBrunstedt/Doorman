//! Signup-request bench: the work `request_signup` does behind an
//! enrollment flow — email normalize/validate, rate-limit check, user
//! provisioning, single-use token issuance, link render, and the (captured,
//! non-networked) email send.
//!
//! Each iteration runs against a fresh, empty manager (built in the
//! untimed `iter_batched` setup) so it measures the steady-state cost of a
//! single provision-and-issue against an empty store. Reusing one manager
//! across iterations would instead measure the cost of an ever-growing
//! token store (the `Vec`-backed in-memory store scans every entry on each
//! write), which is a property of the test double, not the signup path.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-core --bench enrollment
//! ```

mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use doorman_core::session::SessionContext;
use doorman_core::signup::SignupManager;
use tokio::runtime::Runtime;

fn signup_manager() -> SignupManager {
    support::in_memory_core().signup
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
