use axum::http::StatusCode;
use doorman_axum::csrf::CsrfConfig;
use url::Url;

use crate::common::TestApp;

const APP_ORIGIN: &str = "https://app.test";
const EVIL_ORIGIN: &str = "https://evil.test";

#[derive(Debug, Clone, Copy)]
enum Credential {
    Cookie,
    Bearer,
    Both,
}

fn app(csrf: Option<CsrfConfig>) -> TestApp {
    let origin = Url::parse(APP_ORIGIN).expect("origin");
    TestApp::with(
        |b| b,
        move |b| {
            let csrf = csrf.unwrap_or_else(|| CsrfConfig::new(origin.clone()));
            b.external_origin(origin).csrf(csrf)
        },
    )
}

#[tokio::test]
async fn a_cookie_request_that_changes_state_must_come_from_the_application() {
    let evil_referer = format!("{EVIL_ORIGIN}/settings");
    let app_referer = format!("{APP_ORIGIN}/settings");
    let cases = [
        (
            Credential::Cookie,
            Some(("origin", APP_ORIGIN)),
            StatusCode::NO_CONTENT,
        ),
        (
            Credential::Cookie,
            Some(("referer", &app_referer)),
            StatusCode::NO_CONTENT,
        ),
        (
            Credential::Cookie,
            Some(("origin", EVIL_ORIGIN)),
            StatusCode::FORBIDDEN,
        ),
        (
            Credential::Cookie,
            Some(("referer", &evil_referer)),
            StatusCode::FORBIDDEN,
        ),
        (Credential::Cookie, None, StatusCode::FORBIDDEN),
        (Credential::Bearer, None, StatusCode::NO_CONTENT),
        (
            Credential::Both,
            Some(("origin", EVIL_ORIGIN)),
            StatusCode::NO_CONTENT,
        ),
    ];

    for (credential, header, expected) in cases {
        let app = app(None);
        let session = app.session_for("alice@example.com").await;
        let mut call = app.delete(&format!("/auth/sessions/{}", session.session.id));
        call = match credential {
            Credential::Cookie => call.cookie(&session.token),
            Credential::Bearer => call.bearer(&session.token),
            Credential::Both => call.cookie(&session.token).bearer(&session.token),
        };
        if let Some((name, value)) = header {
            call = call.header(name, value);
        }

        let reply = call.send().await;

        let case = format!("{credential:?} {header:?}");
        assert_eq!(reply.status, expected, "{case}");
        if expected == StatusCode::FORBIDDEN {
            assert_eq!(reply.error_code(), "csrf_origin_mismatch", "{case}");
            assert!(app.is_authenticated(&session.token).await, "{case}");
        }
    }
}

#[tokio::test]
async fn a_cookie_read_is_not_checked() {
    let app = app(None);
    let session = app.session_for("alice@example.com").await;

    let reply = app
        .get("/me")
        .cookie(&session.token)
        .header("origin", EVIL_ORIGIN)
        .send()
        .await;

    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn a_disabled_check_lets_a_cross_origin_cookie_request_through() {
    let app = app(Some(CsrfConfig::disabled()));
    let session = app.session_for("alice@example.com").await;

    let reply = app
        .delete(&format!("/auth/sessions/{}", session.session.id))
        .cookie(&session.token)
        .header("origin", EVIL_ORIGIN)
        .send()
        .await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
}
