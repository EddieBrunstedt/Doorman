//! Minimal Axum application using bauth with SQLite storage.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use bauth_axum::dto::{MeResponse, SessionDto, UserDto};
use bauth_axum::prelude::*;
use bauth_core::signup::TOKEN_PLACEHOLDER;
use bauth_core::storage::PasskeyCredentialStore;
use bauth_sqlx::SqliteStorage;
use url::Url;

#[derive(Clone)]
struct AppState {
    passkey_credentials: Arc<dyn PasskeyCredentialStore>,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://bauth-minimal-app.db?mode=rwc".to_owned());
    let external_origin: Url = env::var("EXTERNAL_ORIGIN")
        .unwrap_or_else(|_| "http://localhost:3000".to_owned())
        .parse()?;
    let bind_addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()?;

    let storage = SqliteStorage::connect(&database_url).await?;
    storage.migrate().await?;
    let app_state = AppState {
        passkey_credentials: storage.passkey_credential_store(),
    };

    let rp_id = env::var("PASSKEY_RP_ID")
        .unwrap_or_else(|_| external_origin.host_str().unwrap_or("localhost").to_owned());
    let passkey_config = PasskeyConfig::new(
        rp_id,
        external_origin.clone(),
        env::var("PASSKEY_RP_NAME").unwrap_or_else(|_| "bauth minimal app".to_owned()),
    );

    let cookie_config = CookieConfig {
        secure: external_origin.scheme() == "https",
        ..CookieConfig::default()
    };

    let signup_url_template = format!(
        "{}?signup_token={TOKEN_PLACEHOLDER}",
        external_origin.as_str().trim_end_matches('/')
    );

    let auth = bauth_axum::quickstart(storage.storage())
        .email(Arc::new(TerminalEmailSender))
        .passkey(passkey_config)
        .signup(SignupConfig {
            url_template: signup_url_template,
            ..SignupConfig::default()
        })
        .external_origin(external_origin.clone())
        .cookie(cookie_config)
        .silence_warnings()
        .build()?;
    let app = Router::new()
        .route("/", get(index))
        .route("/api/me", get(me))
        .with_state(app_state)
        .merge(auth.router())
        .layer(auth.session_layer());

    eprintln!("listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn me(
    State(state): State<AppState>,
    auth: AuthSession,
) -> std::result::Result<Json<MeResponse>, axum::http::StatusCode> {
    let passkey_count = state
        .passkey_credentials
        .list_passkeys_for_user(auth.user.id)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .len();
    Ok(Json(MeResponse {
        user: UserDto::from_user(auth.user, passkey_count),
        session: SessionDto::from_session(auth.session, true),
    }))
}
