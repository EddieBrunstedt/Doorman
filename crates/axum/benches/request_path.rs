//! End-to-end request-path benches, driven through the real router and
//! `SessionLayer` via `tower::ServiceExt::oneshot` (no TCP, no `reqwest`).
//!
//! - `me_cached` — `GET /me` with a valid bearer token, cache warm. The
//!   realistic per-request auth overhead a host adds to every endpoint.
//! - `me_uncached` — the same request with the session cache cleared each
//!   iteration, forcing the full store round-trip the layer does on a cold
//!   cache.
//! - `layer_no_auth` — an unauthenticated `GET` through the layer to a
//!   public route, measuring the layer's fixed cost on traffic that carries
//!   no session.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p bauth-axum --bench request_path
//! ```

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use bauth_axum::BauthAxum;
use bauth_axum::SessionCache;
use bauth_axum::config::CookieConfig;
use bauth_axum::dto::UserDto;
use bauth_axum::extractors::AuthSession;
use bauth_core::email::EmailSender;
use bauth_core::memory::{
    InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore, InMemorySessionStore,
    InMemoryUserStore, InMemoryVerificationTokenStore,
};
use bauth_core::passkey::PasskeyConfig;
use bauth_core::session::{SessionContext, SessionManager};
use bauth_core::storage::{PasskeyCredentialStore, Storage, User, UserId, UserStore};
use bauth_test_support::CapturingEmailSender;
use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;
use tower::ServiceExt;

struct Scaffold {
    router: Router,
    cache: SessionCache,
    token: String,
    user_id: UserId,
}

async fn build_scaffold() -> Scaffold {
    let email = Arc::new(CapturingEmailSender::new());
    let user_store: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let session_store: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let token_store: Arc<InMemoryVerificationTokenStore> =
        Arc::new(InMemoryVerificationTokenStore::new());
    let passkey_credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let passkey_challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());

    let rp_origin = url::Url::parse("http://localhost:8080").expect("rp origin");
    let storage = Storage {
        users: user_store.clone(),
        sessions: session_store.clone(),
        verification_tokens: token_store,
        passkey_credentials: passkey_credentials.clone(),
        passkey_challenges,
    };

    let auth = BauthAxum::builder(storage)
        .email(email as Arc<dyn EmailSender>)
        .passkey(PasskeyConfig::new("localhost", rp_origin, "bauth bench"))
        .cookie(CookieConfig {
            secure: false,
            ..CookieConfig::default()
        })
        .silence_warnings()
        .build()
        .expect("auth built");

    let session_manager: SessionManager = auth.state().session_manager().clone();
    let cache = auth.cache().clone();

    // Seed a verified user and a live session token.
    let now = chrono::Utc::now();
    let user = User {
        id: UserId::new(),
        email: Some("bench@example.com".into()),
        email_verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    let user_id = user.id;
    user_store.create_user(user).await.expect("create user");
    let token = session_manager
        .create(user_id, SessionContext::default())
        .await
        .expect("create session")
        .token;

    let passkey_credentials_dyn: Arc<dyn PasskeyCredentialStore> = passkey_credentials;
    let router = Router::new()
        .merge(auth.router())
        .route("/me", get(me_handler))
        .route("/public", get(|| async { StatusCode::OK }))
        .layer(Extension(passkey_credentials_dyn))
        .layer(auth.session_layer());

    Scaffold {
        router,
        cache,
        token,
        user_id,
    }
}

async fn me_handler(
    auth: AuthSession,
    Extension(passkey_credentials): Extension<Arc<dyn PasskeyCredentialStore>>,
) -> Response {
    let passkey_count = passkey_credentials
        .list_passkeys_for_user(auth.user.id)
        .await
        .map(|list| list.len())
        .unwrap_or(0);
    (
        StatusCode::OK,
        Json(UserDto::from_user(auth.user, passkey_count)),
    )
        .into_response()
}

fn me_request(token: &str) -> Request<Body> {
    Request::builder()
        .uri("/me")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("build request")
}

fn request_path(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    let scaffold = runtime.block_on(build_scaffold());

    // Warm the cache once for the cached path.
    runtime.block_on(async {
        let response = scaffold
            .router
            .clone()
            .oneshot(me_request(&scaffold.token))
            .await
            .expect("warm request");
        assert_eq!(response.status(), StatusCode::OK);
    });

    c.bench_function("me_cached", |b| {
        b.to_async(&runtime).iter(|| async {
            let response = scaffold
                .router
                .clone()
                .oneshot(me_request(&scaffold.token))
                .await
                .expect("request");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    c.bench_function("me_uncached", |b| {
        b.to_async(&runtime).iter(|| async {
            scaffold.cache.invalidate_user(scaffold.user_id);
            let response = scaffold
                .router
                .clone()
                .oneshot(me_request(&scaffold.token))
                .await
                .expect("request");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });

    c.bench_function("layer_no_auth", |b| {
        b.to_async(&runtime).iter(|| async {
            let request = Request::builder()
                .uri("/public")
                .body(Body::empty())
                .expect("build request");
            let response = scaffold
                .router
                .clone()
                .oneshot(request)
                .await
                .expect("request");
            assert_eq!(response.status(), StatusCode::OK);
        });
    });
}

criterion_group!(benches, request_path);
criterion_main!(benches);
