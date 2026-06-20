//! The host's whole purge binary.
//!
//! Run it from an external scheduler — cron, AWS EventBridge, a Kubernetes
//! `CronJob` — as a separate, short-lived process. It opens no HTTP port and
//! adds no network surface; it sweeps expired rows once and exits.
//!
//! It is a *leaf* of the dependency graph that knows the backend (via
//! [`app::build_storage`]), which is exactly why it lives here in the host's
//! workspace rather than being shipped by doorman: doorman cannot ship a binary
//! generic over a backend it does not know. doorman ships the backend-blind
//! [`doorman::ops::run_purge`] runner instead, and this five-line `main` hands
//! it the host's own storage.
//!
//! ```sh
//! cargo run -p doorman-purge-example --bin purge
//! cargo run -p doorman-purge-example --bin purge -- --json
//! cargo run -p doorman-purge-example --bin purge -- --now 2026-01-01T00:00:00Z
//! ```

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // The SAME builder the server uses — so this job cannot sweep a different
    // database than the one the app writes to.
    let storage = app::build_storage().await;
    doorman::ops::run_purge(storage).await
}
