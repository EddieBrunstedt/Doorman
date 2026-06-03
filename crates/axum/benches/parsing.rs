//! Request-header parsing microbenches on the CSRF decision path.
//!
//! Every state-changing request runs through [`CsrfLayer`], whose decision
//! parses the `Cookie` header (to detect an ambient session), the
//! `Authorization` header (to detect a bearer bypass), and the `Origin` /
//! `Referer` headers (to check same-origin). These benches isolate that
//! parsing cost from the rest of the request path by driving the layer with a
//! trivial inner service:
//!
//! - `same_origin_allow` — cookie + matching `Origin`: parses the cookie and
//!   origin, then calls the inner service.
//! - `cross_origin_reject` — cookie + mismatched `Origin`: parses both and
//!   short-circuits with a rejection.
//! - `bearer_bypass` — cookie + `Authorization: Bearer`: the bearer parse wins
//!   and the request skips the origin check entirely.
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p doorman-axum --bench parsing
//! ```

use std::convert::Infallible;

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use criterion::{Criterion, criterion_group, criterion_main};
use doorman_axum::{CsrfConfig, CsrfLayer};
use tokio::runtime::Runtime;
use tower::{Layer, ServiceExt, service_fn};
use url::Url;

const SESSION_COOKIE: &str = "doorman_session";
const APP_ORIGIN: &str = "https://app.test";

/// A representative `Cookie` header carrying the session plus a couple of
/// unrelated pairs, so the parse does real splitting work.
fn cookie_header() -> HeaderValue {
    HeaderValue::from_static("theme=dark; doorman_session=session-token-value; locale=en-US")
}

/// Build the header set for one scenario.
fn headers(origin: Option<&'static str>, bearer: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, cookie_header());
    if let Some(origin) = origin {
        headers.insert(header::ORIGIN, HeaderValue::from_static(origin));
    }
    if bearer {
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer some-opaque-bearer-token"),
        );
    }
    headers
}

/// Clone a prebuilt header set into a fresh state-changing request.
fn request(template: &HeaderMap) -> Request<Body> {
    let mut req = Request::new(Body::empty());
    *req.method_mut() = Method::POST;
    *req.headers_mut() = template.clone();
    req
}

fn csrf_parsing(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");

    let inner = service_fn(|_req: Request<Body>| async {
        Ok::<Response, Infallible>(StatusCode::OK.into_response())
    });
    let layer = CsrfLayer::new(
        CsrfConfig::new(Url::parse(APP_ORIGIN).expect("origin")),
        SESSION_COOKIE,
    );
    let service = layer.layer(inner);

    let mut group = c.benchmark_group("csrf");

    let scenarios: [(&str, HeaderMap, StatusCode); 3] = [
        (
            "same_origin_allow",
            headers(Some(APP_ORIGIN), false),
            StatusCode::OK,
        ),
        (
            "cross_origin_reject",
            headers(Some("https://evil.test"), false),
            StatusCode::FORBIDDEN,
        ),
        ("bearer_bypass", headers(None, true), StatusCode::OK),
    ];

    for (name, template, expected) in scenarios {
        group.bench_function(name, |b| {
            b.to_async(&runtime).iter(|| {
                let service = service.clone();
                let req = request(&template);
                async move {
                    let response = service.oneshot(req).await.expect("csrf service");
                    assert_eq!(response.status(), expected);
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, csrf_parsing);
criterion_main!(benches);
