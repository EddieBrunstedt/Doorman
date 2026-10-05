//! Request-header parsing microbenches on the CSRF decision path.
//!
//! Every state-changing request runs through the CSRF origin check inside
//! `SessionLayer`, whose decision parses the `Cookie` header (to detect an
//! ambient session), the `Authorization` header (to detect a bearer bypass),
//! and the `Origin` / `Referer` headers (to check same-origin). These benches
//! drive the real layer with a trivial route behind it, over the in-memory
//! stores with the session cache warm:
//!
//! - `same_origin_allow` — cookie + matching `Origin`: parses the cookie and
//!   origin, then resolves the (cached) session and calls the route.
//! - `cross_origin_reject` — cookie + mismatched `Origin`: parses both and
//!   short-circuits with a rejection before any session resolution.
//! - `bearer_bypass` — cookie + `Authorization: Bearer`: the bearer parse wins,
//!   the request skips the origin check, and the (cached) session resolves.
//!
//! The two allowed paths include a cached session resolution; compare them
//! against `request_path/me_cached` to separate the parsing cost from it.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-axum --bench parsing
//! ```

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::routing::post;
use criterion::{Criterion, criterion_group, criterion_main};
use doorman_axum::AuthService;
use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_core::account::AccountConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::NoopAuditSink;
use doorman_core::clock::SystemClock;
use doorman_core::email::EmailSender;
use doorman_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemoryRateLimiter,
    InMemorySessionStore, InMemoryUserStore, InMemoryVerificationTokenStore,
};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionContext;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::{AccountStatus, Storage, User, UserId, UserStore};
use doorman_test_support::CapturingEmailSender;
use tokio::runtime::Runtime;
use tower::ServiceExt;
use url::Url;

const SESSION_COOKIE: &str = "doorman_session";
const APP_ORIGIN: &str = "https://app.test";

/// Build a router with CSRF checks enabled for [`APP_ORIGIN`] and a seeded
/// live session, returning it with the session's token.
async fn build_router() -> (Router, String) {
    let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let storage = Storage {
        users: user_store.clone(),
        sessions: Arc::new(InMemorySessionStore::new()),
        verification_tokens: Arc::new(InMemoryVerificationTokenStore::new()),
        passkey_credentials: Arc::new(InMemoryPasskeyCredentialStore::new()),
        passkey_challenges: Arc::new(InMemoryPasskeyChallengeStore::new()),
    };

    let rp_origin = Url::parse(APP_ORIGIN).expect("rp origin");
    let core = AuthCore::builder(storage)
        .email(Arc::new(CapturingEmailSender::new()) as Arc<dyn EmailSender>)
        .passkey(PasskeyConfig::new(
            "app.test",
            rp_origin.clone(),
            "doorman bench",
        ))
        .reauthentication(doorman_core::reauth::ReauthPolicy::disabled())
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: "https://app.test/signup?token={token}".to_string(),
            ..SignupConfig::default()
        })
        .recovery(RecoveryConfig {
            url_template: "https://app.test/recovery?token={token}".to_string(),
            ..RecoveryConfig::default()
        })
        .account(AccountConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..AccountConfig::default()
        })
        .build()
        .expect("auth core built");
    let auth = AuthService::builder(core)
        .csrf(CsrfConfig::new(rp_origin))
        .cookie(CookieConfig {
            session_cookie_name: SESSION_COOKIE.to_string(),
            ..CookieConfig::default()
        })
        .build()
        .expect("auth built");

    let now = chrono::Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    user_store.create_user(user).await.expect("create user");
    let token = auth
        .state()
        .session_manager()
        .create(user_id, SessionContext::default())
        .await
        .expect("create session")
        .token;

    let router = Router::new()
        .route("/mutate", post(|| async { StatusCode::OK }))
        .layer(auth.session_layer());
    (router, token)
}

/// Build the header set for one scenario. The `Cookie` header carries the
/// session plus a couple of unrelated pairs, so the parse does real splitting
/// work.
fn headers(token: &str, origin: Option<&'static str>, bearer: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let cookie = format!("theme=dark; {SESSION_COOKIE}={token}; locale=en-US");
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&cookie).expect("cookie header"),
    );
    if let Some(origin) = origin {
        headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
    }
    if bearer {
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
        );
    }
    headers
}

/// Clone a prebuilt header set into a fresh state-changing request.
fn request(template: &HeaderMap) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    *req.method_mut() = Method::POST;
    *req.uri_mut() = "/mutate".parse().expect("uri");
    *req.headers_mut() = template.clone();
    req
}

fn csrf_parsing(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let (router, token) = runtime.block_on(build_router());

    let scenarios: [(&str, HeaderMap, StatusCode); 3] = [
        (
            "same_origin_allow",
            headers(&token, Some(APP_ORIGIN), false),
            StatusCode::OK,
        ),
        (
            "cross_origin_reject",
            headers(&token, Some("https://evil.test"), false),
            StatusCode::FORBIDDEN,
        ),
        ("bearer_bypass", headers(&token, None, true), StatusCode::OK),
    ];

    // Warm the session cache so the allowed paths measure a cached resolve.
    runtime.block_on(async {
        let response = router
            .clone()
            .oneshot(request(&scenarios[0].1))
            .await
            .expect("warm request");
        assert_eq!(response.status(), StatusCode::OK);
    });

    let mut group = c.benchmark_group("csrf");
    for (name, template, expected) in scenarios {
        group.bench_function(name, |b| {
            b.to_async(&runtime).iter(|| {
                let router = router.clone();
                let req = request(&template);
                async move {
                    let response = router.oneshot(req).await.expect("csrf request");
                    assert_eq!(response.status(), expected);
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, csrf_parsing);
criterion_main!(benches);
