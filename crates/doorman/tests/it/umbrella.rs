#![cfg(all(feature = "axum", feature = "sqlite"))]

use std::sync::Arc;

use doorman::core::email_link::TOKEN_PLACEHOLDER;
use doorman::core::memory::InMemoryRateLimiter;
use doorman::prelude::*;
use url::Url;

#[tokio::test]
async fn umbrella_prelude_builds_the_stack() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    let storage = SqliteStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;

    let origin: Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');
    let core = AuthCore::builder(storage.all_stores())
        .email(Arc::new(TerminalEmailSender))
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .reauthentication(ReauthPolicy::required_for([
            ReauthAction::DeleteUser,
            ReauthAction::RemovePasskey,
        ]))
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .user(UserConfig {
            url_template: format!("{base}/user/email?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .build()?;
    let auth = AuthService::builder(core)
        .external_origin(origin)
        .cookie(CookieConfig::default())
        .build()?;

    let _ = auth.router();
    let _ = auth.session_layer();

    let _: Option<doorman::sqlx::SqliteStorage> = None;
    Ok(())
}
