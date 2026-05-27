//! Quickstart builder smoke test.
//!
//! Wires `bauth_axum::quickstart` against the in-memory stores, signs a
//! user in through the HTTP surface, and confirms the resulting session
//! cookie loads back through the session layer. Validates that the
//! quickstart path produces an end-to-end working app without the host
//! constructing managers by hand.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::config::CookieConfig;
use bauth_axum::dto::{AuthResponse, MagicLinkConsumeRequest, RequestMagicLinkRequest, UserDto};
use bauth_axum::extractors::AuthSession;
use bauth_axum::quickstart;
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{MagicLinkConfig, MagicLinkRateLimits, TOKEN_PLACEHOLDER};
use bauth_core::memory::{
    InMemoryEmailSender, InMemoryOAuthIdentityStore, InMemoryOAuthStateStore,
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::storage::Storage;
use reqwest::header;
use tokio::net::TcpListener;

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

#[tokio::test]
async fn quickstart_magic_link_and_me() {
    let email = Arc::new(InMemoryEmailSender::new());
    let storage = Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
        oauth_identities: Arc::new(InMemoryOAuthIdentityStore::new()),
        oauth_states: Arc::new(InMemoryOAuthStateStore::new()),
    };

    let auth = quickstart(storage)
        .email(email.clone() as Arc<dyn EmailSender>)
        .magic_link(MagicLinkConfig {
            url_template: MAGIC_URL.to_string(),
            rate_limits: MagicLinkRateLimits::disabled(),
            ..MagicLinkConfig::default()
        })
        .cookie(CookieConfig {
            secure: false,
            ..CookieConfig::default()
        })
        .build()
        .expect("quickstart built");

    let app = Router::new()
        .merge(auth.router())
        .route("/me", get(me_handler))
        .layer(auth.session_layer());

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");
    let base = format!("http://{addr}");

    let request = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("request magic link");
    assert_eq!(request.status(), StatusCode::NO_CONTENT);

    let sent = email.sent();
    assert_eq!(sent.len(), 1, "one magic-link email queued");
    let token = token_from_email(&sent[0].body_text);

    let consume = client
        .post(format!("{base}/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume magic link");
    assert_eq!(consume.status(), StatusCode::OK);
    let set_cookie = consume
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("set-cookie text")
        .to_owned();
    assert!(set_cookie.contains("bauth_session="));
    let body: AuthResponse = consume.json().await.expect("json");
    assert_eq!(body.user.email.as_deref(), Some("alice@example.com"));

    let me = client
        .get(format!("{base}/me"))
        .send()
        .await
        .expect("me")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(me["email"], "alice@example.com");

    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(1), server).await;
}

fn token_from_email(body: &str) -> String {
    let prefix = MAGIC_URL
        .split(TOKEN_PLACEHOLDER)
        .next()
        .expect("template has prefix");
    let start = body.find(prefix).expect("body contains url prefix");
    let after = &body[start + prefix.len()..];
    after
        .split_whitespace()
        .next()
        .expect("token follows prefix")
        .to_string()
}

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}
