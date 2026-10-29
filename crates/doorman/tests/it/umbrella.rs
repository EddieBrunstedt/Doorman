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
    let core = AuthCore::builder(AuthCoreRequired {
        storage: storage.all_stores(),
        email_sender: Arc::new(TerminalEmailSender),
        audit_sink: Arc::new(NoopAuditSink),
        passkey: PasskeyConfig::new("localhost", origin.clone(), "Example"),
        reauthentication: ReauthPolicy::required_for([
            ReauthAction::DeleteUser,
            ReauthAction::RemovePasskey,
        ]),
        rate_limiting: RateLimiting::enforced(Arc::new(InMemoryRateLimiter::new(Arc::new(
            SystemClock,
        )))),
        links: LinkTemplates {
            signup: LinkTemplate::parse(format!("{base}/signup?token={TOKEN_PLACEHOLDER}"))?,
            recovery: LinkTemplate::parse(format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"))?,
            email_change: LinkTemplate::parse(format!(
                "{base}/user/email?token={TOKEN_PLACEHOLDER}"
            ))?,
        },
    })
    .build()?;
    let auth = AuthService::builder(core, PurgeSchedule::External)
        .cookie(CookieConfig::default())
        .build()?;

    let _ = auth.router();
    let _ = auth.session_layer();

    let _: Option<doorman::sqlx::SqliteStorage> = None;
    Ok(())
}
