//! Verify the umbrella crate re-exports wire up the full stack through a
//! single dependency: `bauth::prelude::*` plus the `bauth::core` /
//! `bauth::axum` / `bauth::sqlx` module paths.

#![cfg(all(feature = "axum", feature = "sqlite"))]

use std::sync::Arc;

use bauth::core::verification::TOKEN_PLACEHOLDER;
use bauth::prelude::*;
use url::Url;

#[tokio::test]
async fn umbrella_prelude_builds_the_stack() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    // `SqliteStorage` comes from the re-exported `bauth-sqlx`, the builder and
    // configs from the re-exported `bauth-axum` prelude (which folds in core).
    let storage = SqliteStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;

    let origin: Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');
    let auth = BauthAxum::builder(storage.storage())
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
    let _: Option<bauth::sqlx::SqliteStorage> = None;
    Ok(())
}
