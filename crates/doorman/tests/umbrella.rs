//! Verify the umbrella crate re-exports wire up the full stack through a
//! single dependency: `doorman::prelude::*` plus the `doorman::core` /
//! `doorman::axum` / `doorman::sqlx` module paths.

#![cfg(all(feature = "axum", feature = "sqlite"))]

use std::sync::Arc;

use doorman::core::verification::TOKEN_PLACEHOLDER;
use doorman::prelude::*;
use url::Url;

#[tokio::test]
async fn umbrella_prelude_builds_the_stack() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    // `SqliteStorage` comes from the re-exported `doorman-sqlx`, the builder and
    // configs from the re-exported `doorman-axum` prelude (which folds in core).
    let storage = SqliteStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;

    let origin: Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');
    let auth = AuthService::builder(storage.storage())
        .email(Arc::new(TerminalEmailSender))
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .signup(SignupConfig {
            url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .external_origin(origin)
        .cookie(CookieConfig::default())
        .build()?;

    let _ = auth.router();
    let _ = auth.session_layer();

    // The module paths resolve too.
    let _: Option<doorman::sqlx::SqliteStorage> = None;
    Ok(())
}
