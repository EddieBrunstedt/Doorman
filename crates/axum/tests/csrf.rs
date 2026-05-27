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
use bauth_axum::dto::{AuthResponse, MagicLinkConsumeRequest, RequestMagicLinkRequest, UserDto};
use bauth_axum::extractors::AuthSession;
use bauth_axum::quickstart;
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{MagicLinkConfig, MagicLinkRateLimits, TOKEN_PLACEHOLDER};
use bauth_core::memory::{
    InMemoryEmailSender, InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::storage::Storage;
use reqwest::header;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

const APP_ORIGIN: &str = "https://app.test";
const EVIL_ORIGIN: &str = "https://evil.test";
const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

struct CsrfApp {
    addr: SocketAddr,
    email: Arc<InMemoryEmailSender>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl CsrfApp {
    async fn start(csrf_config: Option<CsrfConfig>) -> Self {
        let email = Arc::new(InMemoryEmailSender::new());
        let storage = Storage {
            users: Arc::new(InMemoryUserStore::new()),
            sessions: Arc::new(InMemorySessionStore::new()),
            verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
            passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
            passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
        };

        let mut builder = quickstart(storage)
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

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}

fn cookie_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client")
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

async fn login(client: &reqwest::Client, app: &CsrfApp, email_addr: &str) -> AuthResponse {
    let request = client
        .post(app.url("/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: email_addr.into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(request.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    let token = token_from_email(&sent.last().expect("email").body_text);

    let consume = client
        .post(app.url("/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume");
    assert_eq!(consume.status(), StatusCode::OK);
    consume.json().await.expect("auth body")
}

#[tokio::test]
async fn same_origin_post_with_cookie_passes() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    let issued = login(&client, &app, "same-origin@example.com").await;

    // Same-origin DELETE of the caller's own session should succeed.
    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, APP_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let me = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn cross_origin_post_with_cookie_is_rejected() {
    let app = CsrfApp::start(None).await;
    let client = cookie_client();
    let issued = login(&client, &app, "cross-origin@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
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
    let _issued = login(&client, &app, "get@example.com").await;

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
    let issued = login(&client, &app, "bearer@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .bearer_auth(&issued.token)
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_mode_allows_cross_origin_post_with_cookie() {
    let app = CsrfApp::start(Some(CsrfConfig::disabled())).await;
    let client = cookie_client();
    let issued = login(&client, &app, "disabled@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}
