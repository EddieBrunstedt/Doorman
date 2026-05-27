//! Shared test scaffolding: spin up an axum app backed by in-memory storage
//! and the magic-link manager, expose a base URL for `reqwest`, and tear the
//! server down at the end of the test.

#![allow(dead_code)]

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
use bauth_axum::{BauthAxum, SessionCache, SessionCacheConfig};
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::memory::{
    InMemoryEmailSender, InMemoryRateLimiter, InMemorySessionStore, InMemoryUserStore,
    InMemoryVerificationTokenStore,
};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionManager};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

pub struct TestApp {
    pub addr: SocketAddr,
    pub email: Arc<InMemoryEmailSender>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl TestApp {
    pub async fn start(host_routes: Router, secure_cookies: bool) -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let email = Arc::new(InMemoryEmailSender::new());
        let limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryRateLimiter::new(clock.clone()));

        let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let token_store: Arc<InMemoryVerificationTokenStore> =
            Arc::new(InMemoryVerificationTokenStore::new());

        let cache = SessionCache::new(SessionCacheConfig::default());
        let session_manager = SessionManager::new(
            session_store.clone(),
            clock.clone(),
            audit.clone(),
            SessionConfig {
                lifetime: Duration::from_secs(60 * 60),
            },
        )
        .with_invalidation_hook(cache.invalidator());

        let magic_link_manager = MagicLinkManager::new(
            user_store.clone(),
            token_store,
            session_manager.clone(),
            email.clone() as Arc<dyn EmailSender>,
            clock.clone(),
            audit,
            limiter,
            MagicLinkConfig {
                url_template: MAGIC_URL.to_string(),
                rate_limits: MagicLinkRateLimits::disabled(),
                ..MagicLinkConfig::default()
            },
        );

        let cookie_config = CookieConfig {
            secure: secure_cookies,
            ..CookieConfig::default()
        };

        let auth = BauthAxum::builder()
            .session_manager(session_manager)
            .user_store(user_store)
            .magic_link_manager(magic_link_manager)
            .session_cache(cache)
            .cookie_config(cookie_config)
            .build()
            .expect("auth built");

        let app = Router::new()
            .merge(auth.router())
            .route("/me", get(me_handler))
            .merge(host_routes)
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

        TestApp {
            addr,
            email,
            handle,
            shutdown: tx,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// Request a magic link for `email`, pull the token out of the in-memory
/// email queue, consume it, and return the issued session response.
pub async fn login(client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    let before = app.email.sent().len();
    let req = client
        .post(app.url("/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: email.into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(req.status(), StatusCode::NO_CONTENT);

    let sent = app.email.sent();
    assert!(sent.len() > before, "magic-link email queued");
    let token = token_from_email(sent.last().expect("email").body_text.as_str());

    let consume = client
        .post(app.url("/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume");
    assert_eq!(consume.status(), StatusCode::OK);
    consume.json().await.expect("auth body")
}

pub fn token_from_email(body: &str) -> String {
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
    // Echo back just the user, in the same shape the host would typically
    // expose at /api/me. Demonstrates that the extractor sees the user
    // loaded by the session layer.
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}
