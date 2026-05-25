//! Shared test scaffolding: spin up an axum app backed by in-memory storage
//! and the password manager, expose a base URL for `reqwest`, and tear the
//! server down at the end of the test.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::BauthAxum;
use bauth_axum::config::CookieConfig;
use bauth_axum::dto::UserDto;
use bauth_axum::extractors::AuthSession;
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryEmailSender, InMemoryPasswordCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::password::PasswordPolicy;
use bauth_core::password_auth::{PasswordAuthConfig, PasswordAuthManager, PasswordRateLimits};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionManager};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

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
        let password_store: Arc<InMemoryPasswordCredentialStore> =
            Arc::new(InMemoryPasswordCredentialStore::new());
        let token_store: Arc<InMemoryVerificationTokenStore> =
            Arc::new(InMemoryVerificationTokenStore::new());

        let session_manager = SessionManager::new(
            session_store.clone(),
            clock.clone(),
            audit.clone(),
            SessionConfig {
                lifetime: Duration::from_secs(60 * 60),
            },
        );

        let password_manager = PasswordAuthManager::new(
            user_store.clone(),
            password_store,
            token_store,
            session_manager.clone(),
            email.clone() as Arc<dyn EmailSender>,
            clock.clone(),
            audit,
            limiter,
            PasswordAuthConfig {
                password_policy: PasswordPolicy { min_length: 8 },
                rate_limits: PasswordRateLimits::disabled(),
                ..PasswordAuthConfig::default()
            },
        );

        let cookie_config = CookieConfig {
            secure: secure_cookies,
            ..CookieConfig::default()
        };

        let auth = BauthAxum::builder()
            .session_manager(session_manager)
            .user_store(user_store)
            .password_manager(password_manager)
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

async fn me_handler(auth: AuthSession) -> Response {
    // Echo back just the user, in the same shape the host would typically
    // expose at /api/me. Demonstrates that the extractor sees the user
    // loaded by the session layer.
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}
