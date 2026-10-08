use std::{env, io::IsTerminal, net::SocketAddr, sync::Arc};

use axum::{Json, Router, extract::State, response::Html, routing::get};
use doorman_axum::prelude::*;
use doorman_core::email_link::TOKEN_PLACEHOLDER;
use doorman_core::memory::InMemoryRateLimiter;
use doorman_sqlx::SqliteStorage;
use url::Url;

#[derive(Clone)]
struct AppState {
    auth: AuthState,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .compact()
        .try_init();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://doorman-minimal-app.db?mode=rwc".to_owned());
    let external_origin: Url = env::var("EXTERNAL_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_owned())
        .parse()?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;

    let storage = SqliteStorage::connect(&database_url).await?;
    storage.migrate().await?;

    let rp_name = env::var("PASSKEY_RP_NAME").unwrap_or_else(|_| "doorman minimal app".to_owned());
    let passkey_config = match env::var("PASSKEY_RP_ID") {
        Ok(rp_id) => PasskeyConfig::new(rp_id, external_origin.clone(), rp_name),
        Err(_) => PasskeyConfig::from_origin(external_origin.clone(), rp_name)?,
    };
    let cookie_config = CookieConfig {
        secure: external_origin.scheme() == "https",
        ..CookieConfig::default()
    };
    let base = external_origin.as_str().trim_end_matches('/');

    let core = AuthCore::builder(storage.all_stores())
        .email(Arc::new(TerminalEmailSender))
        .passkey(passkey_config)
        .reauthentication(ReauthPolicy::required_for([
            ReauthAction::DeleteUser,
            ReauthAction::RequestEmailChange,
            ReauthAction::RemovePasskey,
        ]))
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
        .user(UserConfig {
            url_template: format!("{base}/?email_change_token={TOKEN_PLACEHOLDER}"),
            ..UserConfig::default()
        })
        .build()?;
    let auth = AuthService::builder(core)
        .external_origin(external_origin)
        .cookie(cookie_config)
        .build()?;

    let app_state = AppState {
        auth: auth.state().clone(),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/api/me", get(me))
        .with_state(app_state)
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

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn me(
    State(state): State<AppState>,
    auth: AuthSession,
    AuthUser(user): AuthUser,
) -> std::result::Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let passkeys = state
        .auth
        .passkey()
        .list_passkeys(user.id)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "user": UserDto::from_user(&user, passkeys.len() as u64),
        "session": SessionDto::new(&auth.session, true),
        "recovery_cool_down_active": auth.session.is_in_recovery_cool_down(),
    })))
}
