//! Minimal Axum application using bauth with SQLite storage.

use std::{env, net::SocketAddr, sync::Arc};

use axum::{Json, Router, extract::State, response::Html, routing::get};
use bauth_axum::prelude::*;
use bauth_core::verification::TOKEN_PLACEHOLDER;
use bauth_sqlx::SqliteStorage;
use url::Url;

#[derive(Clone)]
struct AppState {
    auth: BauthState,
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

    let rp_name = env::var("PASSKEY_RP_NAME").unwrap_or_else(|_| "bauth minimal app".to_owned());
    // The common single-origin case derives `rp_id` from the origin host via
    // `from_origin`. Hosts that need a broader registrable suffix (so one
    // credential works across subdomains) set `PASSKEY_RP_ID` and we keep the
    // explicit `new` path for that.
    let passkey_config = match env::var("PASSKEY_RP_ID") {
        Ok(rp_id) => PasskeyConfig::new(rp_id, external_origin.clone(), rp_name),
        Err(_) => PasskeyConfig::from_origin(external_origin.clone(), rp_name)?,
    };
    let cookie_config = CookieConfig {
        secure: external_origin.scheme() == "https",
        ..CookieConfig::default()
    };
    let base = external_origin.as_str().trim_end_matches('/');

    let auth = BauthAxum::builder(storage.storage())
        .email(Arc::new(TerminalEmailSender))
        .passkey(passkey_config)
        .signup(SignupConfig {
            url_template: format!("{base}/?signup_token={TOKEN_PLACEHOLDER}"),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/?recovery_token={TOKEN_PLACEHOLDER}"),
            ..RecoveryConfig::default()
        })
        .external_origin(external_origin)
        .cookie(cookie_config)
        .silence_warnings()
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
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn me(
    State(state): State<AppState>,
    auth: AuthSession,
) -> std::result::Result<Json<serde_json::Value>, axum::http::StatusCode> {
    let cooldown = auth.is_in_recovery_cooldown();
    let passkey_count = state
        .auth
        .passkey()
        .list_passkey_summaries(auth.user.id)
        .await
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .len();
    Ok(Json(serde_json::json!({
        "user": UserDto::from_user(&auth.user, passkey_count),
        "session": SessionDto::from_session(&auth.session, true),
        "recovery_cooldown_active": cooldown,
    })))
}
