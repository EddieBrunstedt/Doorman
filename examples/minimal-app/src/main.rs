//! Minimal Axum application using bauth with SQLite storage.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use bauth_axum::dto::{MeResponse, SessionDto};
use bauth_axum::prelude::*;
use bauth_core::error::EmailResult;
use bauth_core::magic_link::TOKEN_PLACEHOLDER;
use bauth_sqlx::SqliteStorage;
use url::Url;

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

    let magic_link_url_template = format!(
        "{}?magic_token={TOKEN_PLACEHOLDER}",
        external_origin.as_str().trim_end_matches('/')
    );

    let auth = bauth_axum::quickstart(storage.storage())
        .email(Arc::new(StdoutEmailSender))
        .magic_link(MagicLinkConfig {
            url_template: magic_link_url_template,
            ..MagicLinkConfig::default()
        })
        .passkey(passkey_config)
        .external_origin(external_origin.clone())
        .cookie(cookie_config)
        .build()?;
    let app = Router::new()
        .route("/", get(index))
        .route("/api/me", get(me))
        .merge(auth.router())
        .layer(auth.session_layer());

    eprintln!("listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

struct StdoutEmailSender;

#[async_trait::async_trait]
impl EmailSender for StdoutEmailSender {
    async fn send(&self, email: Email) -> EmailResult<()> {
        eprintln!(
            "\n--- bauth email ---\nTo: {}\nSubject: {}\n\n{}\n--- end bauth email ---\n",
            email.to, email.subject, email.body_text
        );
        Ok(())
    }
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn me(auth: AuthSession) -> Json<MeResponse> {
    Json(MeResponse {
        user: auth.user.into(),
        session: SessionDto::from_session(auth.session, true),
    })
}
