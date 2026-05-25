//! Quickstart builder smoke test.
//!
//! Wires `bauth_axum::quickstart` against the in-memory stores, registers
//! a user through the HTTP surface, and confirms the resulting session
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
use bauth_axum::dto::{AuthResponse, RegisterRequest, UserDto};
use bauth_axum::extractors::AuthSession;
use bauth_axum::quickstart;
use bauth_core::memory::{
    InMemoryOAuthIdentityStore, InMemoryOAuthStateStore, InMemoryPasskeyChallengeStore,
    InMemoryPasskeyCredentialStore, InMemoryPasswordCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::password::PasswordPolicy;
use bauth_core::password_auth::{PasswordAuthConfig, PasswordRateLimits};
use bauth_core::storage::Storage;
use reqwest::header;
use tokio::net::TcpListener;

#[tokio::test]
async fn quickstart_password_register_and_me() {
    let storage = Storage {
        users: Arc::new(InMemoryUserStore::new()),
        sessions: Arc::new(InMemorySessionStore::new()),
        passwords: Arc::new(InMemoryPasswordCredentialStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
        oauth_identities: Arc::new(InMemoryOAuthIdentityStore::new()),
        oauth_states: Arc::new(InMemoryOAuthStateStore::new()),
    };

    let auth = quickstart(storage)
        .password(PasswordAuthConfig {
            password_policy: PasswordPolicy { min_length: 8 },
            rate_limits: PasswordRateLimits::disabled(),
            ..PasswordAuthConfig::default()
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

    let resp = client
        .post(format!("{base}/auth/password/register"))
        .json(&RegisterRequest {
            email: "alice@example.com".into(),
            password: "hunter22hunter22".into(),
        })
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.contains("bauth_session="));
    let body: AuthResponse = resp.json().await.expect("json");
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

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}
