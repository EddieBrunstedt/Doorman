use std::{env, net::SocketAddr, sync::Arc};

use axum::{Router, response::Html, routing::get};
use doorman::core::memory::InMemoryRateLimiter;
use doorman::prelude::*;
use url::Url;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let storage = app::build_storage().await;

    let external_origin: Url = env::var("EXTERNAL_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_owned())
        .parse()?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;
    let base = external_origin.as_str().trim_end_matches('/');

    let core = AuthCore::builder(storage)
        .email(Arc::new(TerminalEmailSender))
        .passkey(PasskeyConfig::from_origin(
            external_origin.clone(),
            "doorman purge example",
        )?)
        .session_cache(SessionCachePolicy::users_only(SessionCacheConfig::default()))
        .reauthentication(ReauthPolicy::disabled())
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: format!("{base}/?signup_token={TOKEN_PLACEHOLDER}"),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/?recovery_token={TOKEN_PLACEHOLDER}"),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: format!("{base}/?email_change_token={TOKEN_PLACEHOLDER}"),
            ..AccountConfig::default()
        })
        .build()?;
    let auth = AuthService::builder(core)
        .external_origin(external_origin.clone())
        .cookie(CookieConfig {
            secure: external_origin.scheme() == "https",
            ..CookieConfig::default()
        })
        .build()?;

    let app = Router::new()
        .route("/", get(|| async { Html("doorman purge example server") }))
        .merge(auth.router())
        .layer(auth.session_layer());

    eprintln!("listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
