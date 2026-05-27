//! Verifies that the session-resolution cache wired in by the builder is
//! actually evicted when the framework-agnostic `SessionManager` revokes a
//! session (single revoke and bulk-by-user). This is the integration-side
//! coverage for the `SessionInvalidationHook` plumbing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::dto::{AuthResponse, MagicLinkConsumeRequest, RequestMagicLinkRequest, UserDto};
use bauth_axum::extractors::AuthSession;
use bauth_axum::{BauthAxum, CookieConfig, SessionCache, SessionCacheConfig};
use bauth_core::audit::{AuditSink, NoopAuditSink};
use bauth_core::clock::{Clock, SystemClock};
use bauth_core::email::EmailSender;
use bauth_core::magic_link::{
    MagicLinkConfig, MagicLinkManager, MagicLinkRateLimits, TOKEN_PLACEHOLDER,
};
use bauth_core::memory::{
    CapturingEmailSender, InMemoryRateLimiter, InMemorySessionStore, InMemoryUserStore,
    InMemoryVerificationTokenStore,
};
use bauth_core::rate_limit::RateLimiter;
use bauth_core::session::{SessionConfig, SessionManager, hash_token};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const MAGIC_URL: &str = "https://app.test/magic-link?token={token}";

struct Harness {
    addr: SocketAddr,
    cache: SessionCache,
    session_manager: SessionManager,
    email: Arc<CapturingEmailSender>,
    handle: JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl Harness {
    async fn start() -> Self {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let audit: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        let email = Arc::new(CapturingEmailSender::new());
        let limiter: Arc<dyn RateLimiter> = Arc::new(InMemoryRateLimiter::new(clock.clone()));

        let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
        let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
        let token_store: Arc<InMemoryVerificationTokenStore> =
            Arc::new(InMemoryVerificationTokenStore::new());

        // Build the cache up-front so its invalidator can be attached to
        // the session manager before the magic-link manager clones it.
        let cache = SessionCache::new(SessionCacheConfig::default());
        let session_manager = SessionManager::new(
            session_store,
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
            clock,
            audit,
            limiter,
            MagicLinkConfig {
                url_template: MAGIC_URL.to_string(),
                rate_limits: MagicLinkRateLimits::disabled(),
                ..MagicLinkConfig::default()
            },
        );

        let auth = BauthAxum::builder()
            .session_manager(session_manager.clone())
            .user_store(user_store)
            .email_sender(email.clone() as Arc<dyn EmailSender>)
            .magic_link_manager(magic_link_manager)
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
        let _ = self.handle.await;
    }
}

async fn me_handler(auth: AuthSession) -> Response {
    (StatusCode::OK, Json(UserDto::from(auth.user))).into_response()
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

async fn login(client: &reqwest::Client, harness: &Harness, email: &str) -> AuthResponse {
    let before = harness.email.sent().len();
    let req = client
        .post(harness.url("/auth/magic-link/request"))
        .json(&RequestMagicLinkRequest {
            email: email.into(),
        })
        .send()
        .await
        .expect("request");
    assert_eq!(req.status(), StatusCode::NO_CONTENT);

    let sent = harness.email.sent();
    assert!(sent.len() > before, "email queued");
    let token = token_from_email(&sent.last().expect("email").body_text);

    let consume = client
        .post(harness.url("/auth/magic-link/consume"))
        .json(&MagicLinkConsumeRequest { token })
        .send()
        .await
        .expect("consume");
    assert_eq!(consume.status(), StatusCode::OK);
    consume.json().await.expect("auth body")
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

    let auth = login(&client, &harness, "alice@example.com").await;

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

    let first = login(&client, &harness, "bob@example.com").await;
    let second = login(&client, &harness, "bob@example.com").await;

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

    let auth = login(&client, &harness, "carol@example.com").await;
    let hash = hash_token(&auth.token);

    // The magic-link consume handler issues a session but the response
    // doesn't pass back through the session layer, so the cache should be
    // cold until the next authenticated request.
    assert!(
        harness.cache.get(&hash).is_none(),
        "consume alone does not warm the cache"
    );

    assert_eq!(me(&client, &harness, &auth.token).await, StatusCode::OK);
    assert!(
        harness.cache.get(&hash).is_some(),
        "first /me populates the cache"
    );

    harness.shutdown().await;
}
