//! Verifies that the session-resolution cache wired in by the builder is
//! actually evicted when the framework-agnostic `SessionManager` revokes a
//! session (single revoke and bulk-by-user). This is the integration-side
//! coverage for the `SessionInvalidationHook` plumbing.
//!
//! Sessions are minted directly via the in-process `SessionManager` (see
//! [`common::login`]) so the test focuses on cache invalidation rather
//! than on rerunning the signup ceremony.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::dto::{AuthResponse, UserDto};
use bauth_axum::extractors::AuthSession;
use bauth_axum::{BauthAxum, CookieConfig, SessionCache, SessionCacheConfig};
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::memory::{CapturingEmailSender, InMemorySessionStore, InMemoryUserStore};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager, hash_token};
use bauth_core::storage::{User, UserId, UserStore};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct Harness {
    addr: SocketAddr,
    cache: SessionCache,
    session_manager: SessionManager,
    user_store: Arc<InMemoryUserStore>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Harness {
    async fn start() -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let email: Arc<dyn EmailSender> = Arc::new(CapturingEmailSender::new());

        let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());

        // Build the cache up-front so its invalidator can be attached to
        // the session manager before any dependent manager clones it.
        let cache = SessionCache::new(SessionCacheConfig::default());
        let session_manager = SessionManager::new(
            session_store,
            clock,
            audit,
            SessionConfig {
                lifetime: Duration::from_secs(60 * 60),
            },
        )
        .with_invalidation_hook(cache.invalidator());

        let auth = BauthAxum::builder()
            .session_manager(session_manager.clone())
            .user_store(user_store.clone())
            .email_sender(email)
            .session_cache(cache.clone())
            .cookie_config(CookieConfig::default())
            .build()
            .expect("auth built");

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
            cache,
            session_manager,
            user_store,
            handle,
            shutdown: tx,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
}

async fn login(harness: &Harness, email: &str) -> AuthResponse {
    let normalized = email.trim().to_ascii_lowercase();
    let user = if let Some(existing) = harness
        .user_store
        .find_user_by_email(&normalized)
        .await
        .expect("find user")
    {
        existing
    } else {
        let now = chrono::Utc::now();
        let user = User {
            id: UserId::new(),
            email: Some(normalized),
            email_verified_at: Some(now),
            created_at: now,
            updated_at: now,
        };
        harness
            .user_store
            .create_user(user.clone())
            .await
            .expect("create user");
        user
    };
    let issued = harness
        .session_manager
        .create(user.id, SessionContext::default())
        .await
        .expect("create session");
    AuthResponse::from_issued(user, issued)
}

async fn me(client: &reqwest::Client, harness: &Harness, token: &str) -> StatusCode {
    client
        .get(harness.url("/me"))
        .bearer_auth(token)
        .send()
        .await
        .expect("me")
        .status()
}

#[tokio::test]
async fn revoke_invalidates_cache() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();

    let auth = login(&harness, "alice@example.com").await;

    // First /me populates the cache.
    assert_eq!(me(&client, &harness, &auth.token).await, StatusCode::OK);
    assert!(
        harness.cache.get(&hash_token(&auth.token)).is_some(),
        "cache populated on first authenticated request"
    );

    // Revoke through the framework-agnostic manager — the cache should
    // see the invalidation hook fire and drop the entry.
    harness
        .session_manager
        .revoke(&auth.token)
        .await
        .expect("revoke");
    assert!(
        harness.cache.get(&hash_token(&auth.token)).is_none(),
        "revoke evicts the cached entry"
    );

    // And the wire reflects it: next request is 401, not 200 from a
    // stale cache.
    assert_eq!(
        me(&client, &harness, &auth.token).await,
        StatusCode::UNAUTHORIZED,
        "request after revoke is unauthorised, not a stale cache hit"
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn revoke_all_for_user_invalidates_cache() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();

    let first = login(&harness, "bob@example.com").await;
    let second = login(&harness, "bob@example.com").await;

    assert_eq!(me(&client, &harness, &first.token).await, StatusCode::OK);
    assert_eq!(me(&client, &harness, &second.token).await, StatusCode::OK);
    assert!(harness.cache.get(&hash_token(&first.token)).is_some());
    assert!(harness.cache.get(&hash_token(&second.token)).is_some());

    // Bulk-revoke through the SessionManager.
    let removed = harness
        .session_manager
        .revoke_all_for_user(first.user.id)
        .await
        .expect("revoke_all_for_user");
    assert_eq!(removed, 2);

    assert!(
        harness.cache.get(&hash_token(&first.token)).is_none(),
        "bulk revoke evicts first session"
    );
    assert!(
        harness.cache.get(&hash_token(&second.token)).is_none(),
        "bulk revoke evicts second session"
    );

    assert_eq!(
        me(&client, &harness, &first.token).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        me(&client, &harness, &second.token).await,
        StatusCode::UNAUTHORIZED
    );

    harness.shutdown().await;
}

#[tokio::test]
async fn cache_warms_on_first_authenticated_request() {
    let harness = Harness::start().await;
    let client = reqwest::Client::new();

    let auth = login(&harness, "carol@example.com").await;
    let hash = hash_token(&auth.token);

    assert!(
        harness.cache.get(&hash).is_none(),
        "direct session creation does not warm the cache"
    );

    assert_eq!(me(&client, &harness, &auth.token).await, StatusCode::OK);
    assert!(
        harness.cache.get(&hash).is_some(),
        "first /me populates the cache"
    );

    harness.shutdown().await;
}
