//! End-to-end HTTP tests for the magic-link routes.
//!
//! Exercises the quickstart wiring path so the test covers manager
//! construction, route mounting, email delivery, session cookie issuance,
//! and the session layer loading the newly issued session.

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
use tokio::task::JoinHandle;

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

struct MagicLinkApp {
    addr: SocketAddr,
    email: Arc<InMemoryEmailSender>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl MagicLinkApp {
    async fn start() -> Self {
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
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                })
                .await
                .expect("serve");
        });

        Self {
            addr,
            email,
            handle,
            shutdown: tx,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
    }
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

#[tokio::test]
async fn request_consume_and_me_cookie_path() {
    let app = MagicLinkApp::start().await;
    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client");

    let request = client
        .post(app.url("/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: "Alice@Example.com".into(),
        })
        .send()
        .await
        .expect("request magic link");
    assert_eq!(request.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    assert_eq!(sent.len(), 1, "one magic-link email queued");
    assert_eq!(sent[0].to, "alice@example.com");
    assert_eq!(sent[0].subject, "Your sign-in link");
    let token = token_from_email(&sent[0].body_text);

    let consume = client
        .post(app.url("/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume magic link");
    assert_eq!(consume.status(), StatusCode::OK);
    let set_cookie = consume
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie present")
        .to_str()
        .expect("set-cookie text")
        .to_owned();
    assert!(set_cookie.contains("bauth_session="));
    assert!(set_cookie.contains("HttpOnly"));

    let body: AuthResponse = consume.json().await.expect("json");
    assert_eq!(body.user.email.as_deref(), Some("alice@example.com"));
    assert!(body.user.email_verified);
    assert!(!body.token.is_empty());

    let me = client
        .get(app.url("/me"))
        .send()
        .await
        .expect("me")
        .json::<serde_json::Value>()
        .await
        .expect("json");
    assert_eq!(me["email"], "alice@example.com");

    let bearer = reqwest::Client::new()
        .get(app.url("/me"))
        .bearer_auth(&body.token)
        .send()
        .await
        .expect("bearer me");
    assert_eq!(bearer.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn invalid_token_returns_400_with_code() {
    let app = MagicLinkApp::start().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest {
            token: "not-a-real-token".into(),
        })
        .send()
        .await
        .expect("consume");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "invalid_verification_token");

    app.shutdown().await;
}

#[tokio::test]
async fn invalid_email_returns_400_with_code() {
    let app = MagicLinkApp::start().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: "not-an-email".into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"]["code"], "invalid_email");

    app.shutdown().await;
}

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}
