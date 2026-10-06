use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::routing::post;
use criterion::{Criterion, criterion_group, criterion_main};
use doorman_axum::AuthService;
use doorman_axum::config::CookieConfig;
use doorman_axum::csrf::CsrfConfig;
use doorman_core::assembly::AuthCore;
use doorman_core::audit::NoopAuditSink;
use doorman_core::clock::SystemClock;
use doorman_core::email::EmailSender;
use doorman_core::memory::{
    InMemoryEmailLinkStore, InMemoryPasskeyChallengeStore, InMemoryPasskeyStore,
    InMemoryRateLimiter, InMemorySessionStore, InMemoryUserStore,
};
use doorman_core::passkey::PasskeyConfig;
use doorman_core::recovery::RecoveryConfig;
use doorman_core::session::SessionContext;
use doorman_core::signup::SignupConfig;
use doorman_core::storage::{Storage, User, UserId, UserStatus, UserStore};
use doorman_core::user::UserConfig;
use doorman_test_support::CapturingEmailSender;
use tokio::runtime::Runtime;
use tower::ServiceExt;
use url::Url;

const SESSION_COOKIE: &str = "doorman_session";
const APP_ORIGIN: &str = "https://app.test";

async fn build_router() -> (Router, String) {
    let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let storage = Storage {
        users: user_store.clone(),
        sessions: Arc::new(InMemorySessionStore::new()),
        email_links: Arc::new(InMemoryEmailLinkStore::new()),
        passkeys: Arc::new(InMemoryPasskeyStore::new()),
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
        .user(UserConfig {
            url_template: "https://app.test/email-change?token={token}".to_string(),
            ..UserConfig::default()
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
        status: UserStatus::Active,
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
