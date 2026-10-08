use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let storage = app::build_storage().await;
    doorman::ops::run_purge(storage.expiring).await
}
