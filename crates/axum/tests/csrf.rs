//! HTTP tests for the CSRF origin-check layer.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::config::CookieConfig;
use bauth_axum::csrf::CsrfConfig;
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
use tokio::task::JoinHandle;
use url::Url;

const APP_ORIGIN: &str = "https://app.test";
const EVIL_ORIGIN: &str = "https://evil.test";

struct CsrfApp {
    addr: SocketAddr,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl CsrfApp {
    async fn start(csrf_config: Option<CsrfConfig>) -> Self {
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

        let mut builder = quickstart(storage)
            .password(PasswordAuthConfig {
                password_policy: PasswordPolicy { min_length: 8 },
                rate_limits: PasswordRateLimits::disabled(),
                ..PasswordAuthConfig::default()
            })
            .cookie(CookieConfig {
                secure: false,
                ..CookieConfig::default()
            })
            .external_origin(Url::parse(APP_ORIGIN).expect("valid app origin"))
            .silence_warnings();

        if let Some(config) = csrf_config {
            builder = builder.with_csrf(config);
        }

        let auth = builder.build().expect("auth built");
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

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}

fn cookie_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client")
}

async fn register(client: &reqwest::Client, app: &CsrfApp, email: &str) -> AuthResponse {
    let resp = client
        .post(app.url("/auth/password/register"))
        .json(&RegisterRequest {
            email: email.into(),
            password: "hunter22hunter22".into(),
        })
        .send()
        .await
        .expect("register");
    assert_eq!(resp.status(), StatusCode::CREATED);
    resp.json().await.expect("register body")
}

#[tokio::test]
async fn same_origin_post_with_cookie_passes() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    register(&client, &app, "same-origin@example.com").await;

    let resp = client
        .post(app.url("/auth/password/logout"))
        .header(header::ORIGIN, APP_ORIGIN)
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let me = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn cross_origin_post_with_cookie_is_rejected() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    register(&client, &app, "cross-origin@example.com").await;

    let resp = client
        .post(app.url("/auth/password/logout"))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "csrf_origin_mismatch");

    let me = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn get_with_cookie_is_unaffected() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    register(&client, &app, "get@example.com").await;

    let resp = client
        .get(app.url("/me"))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn bearer_request_is_unaffected_even_with_cookie() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    let issued = register(&client, &app, "bearer@example.com").await;

    let resp = client
        .post(app.url("/auth/password/logout"))
        .bearer_auth(&issued.token)
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_mode_allows_cross_origin_post_with_cookie() {
    let app = CsrfApp::start(Some(CsrfConfig::disabled())).await;
    let client = cookie_client();
    register(&client, &app, "disabled@example.com").await;

    let resp = client
        .post(app.url("/auth/password/logout"))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("logout");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}
