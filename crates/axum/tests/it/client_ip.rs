use std::net::SocketAddr;
use std::sync::Arc;

use crate::common::{self, PEER, TestApp};
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::{Json, Router, routing::get};
use chrono::{Duration, TimeZone, Utc};
use doorman_axum::prelude::*;
use doorman_core::audit::{Actor, AuditEventKind};
use doorman_core::memory::{InMemoryRateLimiter, InMemoryStorage};
use doorman_core::rate_limit::RateLimits;
use doorman_test_support::{CapturingEmailSender, InMemoryAuditSink, MockClock};
use serde_json::{Value, json};
use tower::ServiceExt;

const START: &str = "/auth/passkey/authenticate/start";
const ORIGIN: &str = "http://localhost:8080";

fn clock() -> Arc<MockClock> {
    Arc::new(MockClock::new(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .expect("timestamp"),
    ))
}

fn router(limits: RateLimits) -> (Router, Arc<MockClock>, Arc<InMemoryAuditSink>) {
    let clock = clock();
    let audit = Arc::new(InMemoryAuditSink::new());
    let passkey = PasskeyConfig::new("localhost", ORIGIN.parse().expect("origin"), "tests");
    let core = AuthCore::builder(AuthCoreRequired {
        storage: InMemoryStorage::new().all_stores(),
        email_sender: Arc::new(CapturingEmailSender::new()),
        audit_sink: audit.clone(),
        passkey,
        reauthentication: ReauthPolicy::disabled(),
        rate_limiting: RateLimiting::Enforced {
            limiter: Arc::new(InMemoryRateLimiter::new(clock.clone())),
            limits,
        },
        links: common::link_templates(),
    })
    .clock(clock.clone())
    .build()
    .expect("auth core built");
    let auth = AuthService::builder(core, PurgeSchedule::external())
        .build()
        .expect("build");
    let app = Router::new()
        .merge(auth.router())
        .route(
            "/context",
            get(|RequestContext(ctx): RequestContext| async move {
                Json(json!({"ip": ctx.ip(), "user_agent": ctx.user_agent()}))
            }),
        )
        .layer(auth.session_layer());
    (app, clock, audit)
}

fn request(path: &str, peer: Option<&str>, client_ip: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method(if path == "/context" { "GET" } else { "POST" })
        .uri(path)
        .header("origin", ORIGIN)
        .body(Body::empty())
        .expect("request");
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(ConnectInfo(peer.parse::<SocketAddr>().expect("socket")));
    }
    if let Some(ip) = client_ip {
        request
            .extensions_mut()
            .insert(ip.parse::<ClientIp>().expect("IP address"));
    }
    request
}

async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.expect("response")
}

async fn body(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body"),
    )
    .expect("json")
}

#[tokio::test]
async fn real_socket_enforces_default_limit_and_ignores_spoofed_headers() {
    let clock = clock();
    let app = TestApp::with(
        |r| {
            common::harness_core(AuthCoreRequired {
                rate_limiting: common::harness_rate_limiting(clock.clone()),
                ..r
            })
            .clock(clock)
        },
        |b| b,
    );
    let server = app.serve().await;
    let client = reqwest::Client::new();
    for n in 1..=61 {
        let response = client.post(server.url(START)).send().await.expect("start");
        assert_eq!(
            response.status(),
            if n <= 60 {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            },
            "request {n}"
        );
    }
    for headers in [
        vec![("x-forwarded-for", "203.0.113.1")],
        vec![("x-real-ip", "203.0.113.2")],
        vec![
            ("x-forwarded-for", "203.0.113.3"),
            ("x-real-ip", "203.0.113.4"),
        ],
    ] {
        let mut request = client.post(server.url(START));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request.send().await.expect("spoofed start");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "60");
        assert_eq!(
            response.json::<Value>().await.expect("body")["error"]["code"],
            "rate_limited"
        );
    }

    server.shutdown().await;
}

#[tokio::test]
async fn socket_buckets_ignore_ports_and_normalize_mapped_ipv4() {
    let (app, clock, _) = router(RateLimits::default());
    for port in 1000..1060 {
        assert_eq!(
            send(
                &app,
                request(START, Some(&format!("192.0.2.1:{port}")), None)
            )
            .await
            .status(),
            StatusCode::OK
        );
    }
    for peer in ["192.0.2.1:9000", "[::ffff:192.0.2.1]:9001"] {
        assert_eq!(
            send(&app, request(START, Some(peer), None)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    for peer in ["192.0.2.2:1000", "[2001:db8::1]:1000"] {
        assert_eq!(
            send(&app, request(START, Some(peer), None)).await.status(),
            StatusCode::OK
        );
    }
    clock.advance(Duration::seconds(60));
    assert_eq!(
        send(&app, request(START, Some("192.0.2.1:1000"), None))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn trusted_extension_overrides_socket_and_canonicalizes_ipv6_buckets() {
    let (app, _, _) = router(RateLimits::default());
    for n in 0..60 {
        let ip = if n % 2 == 0 {
            "2001:db8::1"
        } else {
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        };
        assert_eq!(
            send(&app, request(START, Some("10.0.0.1:1234"), Some(ip)))
                .await
                .status(),
            StatusCode::OK
        );
    }
    assert_eq!(
        send(&app, request(START, None, Some("2001:db8::1")))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        send(
            &app,
            request(START, Some("10.0.0.1:1234"), Some("2001:db8::2"))
        )
        .await
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&app, request(START, Some("10.0.0.1:1234"), None))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn forwarding_headers_never_supply_or_override_identity() {
    let (app, _, _) = router(RateLimits::default());
    for (peer, trusted, expected) in [
        (Some("192.0.2.1:1234"), None, Some("192.0.2.1")),
        (
            Some("192.0.2.1:1234"),
            Some("2001:0db8::1"),
            Some("2001:db8::1"),
        ),
        (None, Some("::ffff:192.0.2.2"), Some("192.0.2.2")),
        (None, None, None),
    ] {
        let mut req = request("/context", peer, trusted);
        let headers = req.headers_mut();
        headers.append(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.1, 10.0.0.1"),
        );
        headers.append("x-forwarded-for", HeaderValue::from_static("invalid"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.2"));
        headers.insert("forwarded", HeaderValue::from_static("for=203.0.113.3"));
        headers.insert("user-agent", HeaderValue::from_static("test agent"));
        let response = send(&app, req).await;
        assert_eq!(
            response.status(),
            if expected.is_some() {
                StatusCode::OK
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        );
        let body = body(response).await;
        if let Some(ip) = expected {
            assert_eq!(body["ip"], ip);
            assert_eq!(body["user_agent"], "test agent");
        } else {
            assert_eq!(
                body,
                json!({"error": {"code": "internal_error", "message": "internal server error"}})
            );
        }
    }
}

#[tokio::test]
async fn missing_identity_fails_closed_and_policy_disabling_is_explicit() {
    for limits in [RateLimits::default(), RateLimits::disabled()] {
        let (app, _, audit) = router(limits);
        for path in [START, "/auth/signup/request", "/auth/recovery/request"] {
            let response = send(&app, request(path, None, None)).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(body(response).await["error"]["code"], "internal_error");
        }
        assert!(audit.events().is_empty(), "no flow runs without identity");
        if limits.login_start_per_ip.is_none() {
            for _ in 0..61 {
                assert_eq!(
                    send(&app, request(START, Some("192.0.2.1:1234"), None))
                        .await
                        .status(),
                    StatusCode::OK
                );
            }
        }
    }
}

#[tokio::test]
async fn signup_and_recovery_charge_socket_ip_and_audit_it() {
    for (path, limit) in [("/auth/signup/request", 5), ("/auth/recovery/request", 20)] {
        let (app, _, audit) = router(RateLimits::default());
        for n in 0..=limit {
            let mut req = request(path, Some("192.0.2.1:1234"), None);
            req.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/json"));
            req.headers_mut().insert(
                "x-forwarded-for",
                HeaderValue::from_str(&format!("203.0.113.{n}")).expect("header"),
            );
            *req.body_mut() =
                Body::from(json!({"email": format!("user{n}@example.com")}).to_string());
            let response = send(&app, req).await;
            assert_eq!(
                response.status(),
                if n < limit {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                }
            );
        }
        let events = audit.events();
        assert!(!events.is_empty());
        for event in events {
            assert!(
                matches!(event.actor, Actor::Subject { ip, .. } if ip.to_string() == "192.0.2.1")
            );
        }
    }
}

#[tokio::test]
async fn signup_session_and_audit_record_the_peer_despite_spoofing() {
    let audit = Arc::new(InMemoryAuditSink::new());
    let app = TestApp::with(
        |r| {
            common::harness_core(AuthCoreRequired {
                audit_sink: audit.clone(),
                ..r
            })
        },
        |b| b,
    )
    .default_header("x-forwarded-for", "203.0.113.1")
    .default_header("x-real-ip", "203.0.113.2")
    .default_header("user-agent", "signup agent");

    let (auth, _) = app.signup("identity@example.com").await;

    let proof = auth
        .key()
        .presented("GET", "/me", Some(&auth.token), chrono::Utc::now());
    let key = app
        .sessions
        .prove_dpop(&proof, Some(&auth.token))
        .await
        .expect("a valid proof");
    let session = app
        .sessions
        .resolve(&auth.token, &RequestTransport::Dpop(key))
        .await
        .expect("resolve")
        .expect("a live session");
    assert_eq!(session.ip.to_string(), PEER);
    assert_eq!(session.user_agent.as_deref(), Some("signup agent"));
    let events = audit.events();
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, AuditEventKind::SessionCreated { .. }))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.kind, AuditEventKind::PasskeyAdded { .. }))
    );
    for event in events {
        assert!(
            matches!(event.actor, Actor::Subject { ip, user_agent: Some(ref ua) } if ip.to_string() == PEER && ua == "signup agent")
        );
    }
}

#[tokio::test]
async fn log_out_audits_the_session_and_its_request_not_the_login() {
    let audit = Arc::new(InMemoryAuditSink::new());
    let app = TestApp::with(
        |r| {
            common::harness_core(AuthCoreRequired {
                audit_sink: audit.clone(),
                ..r
            })
        },
        |b| b,
    );
    let alice = app.session_for("alice@example.com").await;

    let reply = app
        .post("/auth/logout")
        .session(&alice)
        .header("user-agent", "logout agent")
        .send()
        .await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    let logged_out = audit
        .events()
        .into_iter()
        .find(|event| matches!(event.kind, AuditEventKind::LoggedOut { .. }))
        .expect("log out audited");
    assert_eq!(
        logged_out.actor,
        Actor::Session {
            session_id: alice.session.id,
            ip: PEER.parse().expect("peer"),
            user_agent: Some("logout agent".to_owned()),
        },
    );
}
