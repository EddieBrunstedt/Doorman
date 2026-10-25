use axum::http::{Method, StatusCode};
use doorman_axum::dto::PasskeyChallenge;
use doorman_core::passkey::PasskeyConfig;
use url::Url;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::common::{Call, Client, RP_ORIGIN, TestApp, rp_origin};

const EVIL_ORIGIN: &str = "https://evil.test";
const RELATED_ORIGIN: &str = "https://related.test";
const HOST_TRUSTED_ORIGIN: &str = "https://admin.app.test";

fn from_another_site(call: Call<'_>) -> Call<'_> {
    call.header("sec-fetch-site", "cross-site")
        .header("origin", EVIL_ORIGIN)
}

fn with_cookie<'a>(call: Call<'a>, token: &str) -> Call<'a> {
    call.header("cookie", &format!("doorman_session={token}"))
}

#[tokio::test]
async fn a_request_from_another_site_is_refused_on_every_route_that_changes_state() {
    let routes = [
        (Method::POST, "/auth/signup/request"),
        (Method::POST, "/auth/signup/redeem"),
        (Method::POST, "/auth/signup/finish"),
        (Method::POST, "/auth/recovery/request"),
        (Method::POST, "/auth/recovery/redeem"),
        (Method::POST, "/auth/recovery/finish"),
        (Method::POST, "/auth/passkey/authenticate/start"),
        (Method::POST, "/auth/passkey/authenticate/finish"),
        (Method::POST, "/auth/passkey/register/start"),
        (Method::POST, "/auth/passkey/register/finish"),
        (Method::DELETE, "/auth/passkey/AAAA"),
        (Method::PATCH, "/auth/passkey/AAAA"),
        (Method::POST, "/auth/reauth/start"),
        (Method::POST, "/auth/logout"),
        (Method::POST, "/auth/logout-all"),
        (Method::DELETE, "/auth/sessions"),
        (
            Method::DELETE,
            "/auth/sessions/00000000-0000-0000-0000-000000000000",
        ),
        (Method::POST, "/auth/user/email"),
        (Method::POST, "/auth/user/email/confirm"),
        (Method::DELETE, "/auth/user"),
    ];
    let app = TestApp::new();

    for (method, path) in routes {
        let reply = from_another_site(app.call(method.clone(), path))
            .json(&serde_json::json!({ "email": "alice@example.com", "token": "t" }))
            .send()
            .await;

        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(
            reply.error_code(),
            "csrf_origin_mismatch",
            "{method} {path}"
        );
    }
    assert!(app.email.sent().is_empty(), "a refused request sent email");
}

#[tokio::test]
async fn another_site_cannot_log_the_browser_in() {
    let app = TestApp::new();
    let (_, mut mallory) = app.signup("mallory@example.com").await;
    let credential_id = mallory.credential_ids()[0].clone();
    let start = app.post("/auth/passkey/authenticate/start").send().await;
    let challenge: PasskeyChallenge<RequestChallengeResponse> = start.json();
    let login = serde_json::json!({
        "challenge_id": challenge.challenge_id,
        "response": mallory.do_authentication(challenge.options, &credential_id),
    });

    let forged = from_another_site(app.post("/auth/passkey/authenticate/finish"))
        .json(&login)
        .send()
        .await;

    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(forged.set_cookie().is_none());
    let own = app
        .post("/auth/passkey/authenticate/finish")
        .header("sec-fetch-site", "same-origin")
        .json(&login)
        .send()
        .await;
    assert_eq!(
        own.status,
        StatusCode::OK,
        "the refusal used up the challenge"
    );
}

#[tokio::test]
async fn a_cookie_request_that_changes_state_must_come_from_the_application() {
    type Headers = &'static [(&'static str, &'static str)];
    let cases: [(Client, Headers, StatusCode); 6] = [
        (
            Client::Browser,
            &[("sec-fetch-site", "same-origin")],
            StatusCode::NO_CONTENT,
        ),
        (
            Client::Browser,
            &[("origin", RP_ORIGIN)],
            StatusCode::NO_CONTENT,
        ),
        (
            Client::Browser,
            &[("sec-fetch-site", "cross-site"), ("origin", EVIL_ORIGIN)],
            StatusCode::FORBIDDEN,
        ),
        (
            Client::Browser,
            &[("referer", "http://localhost:8080/settings")],
            StatusCode::FORBIDDEN,
        ),
        (Client::Browser, &[], StatusCode::FORBIDDEN),
        (
            Client::Bearer,
            &[("sec-fetch-site", "cross-site"), ("origin", EVIL_ORIGIN)],
            StatusCode::NO_CONTENT,
        ),
    ];

    for (client, headers, expected) in cases {
        let app = TestApp::new();
        let session = app.session_as(client, "alice@example.com").await;
        let mut call = app.delete(&format!("/auth/sessions/{}", session.session.id));
        call = match client {
            Client::Browser => with_cookie(call, &session.token),
            Client::Bearer => call.bearer(&session.token),
        };
        for (name, value) in headers {
            call = call.header(name, value);
        }

        let reply = call.send().await;

        let case = format!("{client:?} {headers:?}");
        assert_eq!(reply.status, expected, "{case}");
        if expected == StatusCode::FORBIDDEN {
            assert_eq!(reply.error_code(), "csrf_origin_mismatch", "{case}");
            assert!(app.is_authenticated(&session).await, "{case}");
        }
    }
}

#[tokio::test]
async fn the_relying_party_origins_and_the_hosts_trusted_origins_are_the_application() {
    let related: Url = RELATED_ORIGIN.parse().expect("origin");
    let host_trusted: Url = HOST_TRUSTED_ORIGIN.parse().expect("origin");
    let cases = [
        (RP_ORIGIN, StatusCode::NO_CONTENT),
        (RELATED_ORIGIN, StatusCode::NO_CONTENT),
        (HOST_TRUSTED_ORIGIN, StatusCode::NO_CONTENT),
        (EVIL_ORIGIN, StatusCode::FORBIDDEN),
    ];

    for (origin, expected) in cases {
        let related = related.clone();
        let host_trusted = host_trusted.clone();
        let app = TestApp::with(
            |b| {
                b.passkey(PasskeyConfig {
                    additional_origins: vec![related],
                    ..PasskeyConfig::new("localhost", rp_origin(), "doorman tests")
                })
            },
            |b| b.trusted_origin(host_trusted),
        );
        let session = app.session_as(Client::Browser, "alice@example.com").await;

        let reply = with_cookie(app.post("/auth/logout"), &session.token)
            .header("sec-fetch-site", "cross-site")
            .header("origin", origin)
            .send()
            .await;

        assert_eq!(reply.status, expected, "{origin}");
    }
}

#[tokio::test]
async fn a_cookie_read_is_not_checked() {
    let app = TestApp::new();
    let session = app.session_as(Client::Browser, "alice@example.com").await;

    let reply = from_another_site(with_cookie(app.get("/me"), &session.token))
        .send()
        .await;

    assert_eq!(reply.status, StatusCode::OK);
}
