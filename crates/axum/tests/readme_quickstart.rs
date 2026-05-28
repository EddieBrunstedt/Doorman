//! Compile-check the README quickstart wiring.

use std::sync::Arc;

use axum::{Router, routing::get};
use bauth_axum::prelude::*;
use bauth_core::signup::TOKEN_PLACEHOLDER;
use bauth_sqlx::SqliteStorage;
use url::Url;

#[tokio::test]
async fn readme_quickstart_snippet_compiles() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    async fn me(auth: AuthSession) -> String {
        auth.user.email.unwrap_or_else(|| "unknown".to_owned())
    }

    let storage = SqliteStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;
    let origin: Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');
    let auth = bauth_axum::quickstart(storage.storage())
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
    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(me))
        .layer(auth.session_layer());
    let _ = app;
    Ok(())
}
