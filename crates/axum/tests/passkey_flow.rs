//! End-to-end HTTP tests for the passkey routes.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::BauthAxum;
use bauth_axum::config::CookieConfig;
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    CapturingEmailSender, InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore,
    InMemorySessionStore, InMemoryUserStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::session::{SessionConfig, SessionManager};
use bauth_core::storage::{PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, UserStore};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

struct PasskeyApp {
    addr: SocketAddr,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl PasskeyApp {
    async fn start() -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let passkey_credentials: Arc<InMemoryPasskeyCredentialStore> =
            Arc::new(InMemoryPasskeyCredentialStore::new());
        let passkey_challenges: Arc<InMemoryPasskeyChallengeStore> =
            Arc::new(InMemoryPasskeyChallengeStore::new());

        let session_manager = SessionManager::new(
            sessions as Arc<dyn SessionStore>,
            clock.clone(),
            audit.clone(),
            SessionConfig {
                lifetime: Duration::from_secs(60 * 60),
            },
        );
        let passkey_manager = PasskeyManager::new(
            users.clone() as Arc<dyn UserStore>,
            passkey_credentials as Arc<dyn PasskeyCredentialStore>,
            passkey_challenges as Arc<dyn PasskeyChallengeStore>,
            session_manager.clone(),
            clock,
            audit,
            PasskeyConfig::new(
                "localhost",
                Url::parse("http://localhost:8080").expect("valid rp origin"),
                "bauth tests",
            ),
        )
        .expect("passkey manager");

        let email_sender: Arc<dyn EmailSender> = Arc::new(CapturingEmailSender::new());

        let auth = BauthAxum::builder()
            .session_manager(session_manager)
            .user_store(users)
            .email_sender(email_sender)
            .passkey_manager(passkey_manager)
            .cookie_config(CookieConfig {
                secure: false,
                ..CookieConfig::default()
            })
            .build()
            .expect("auth built");

        let app = Router::new().merge(auth.router());
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

#[tokio::test]
async fn authenticate_start_accepts_empty_body_and_returns_discoverable_options() {
    let app = PasskeyApp::start().await;
    let client = reqwest::Client::new();

    let response = client
        .post(app.url("/auth/passkey/authenticate/start"))
        .send()
        .await
        .expect("request authenticate start");
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.json::<Value>().await.expect("json body");
    assert!(body["challenge_id"].as_str().is_some());
    assert_eq!(
        body["options"]["publicKey"]["allowCredentials"]
            .as_array()
            .expect("allowCredentials array")
            .len(),
        0
    );

    app.shutdown().await;
}
