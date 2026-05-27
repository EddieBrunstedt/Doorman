//! HTTP tests for the CSRF origin-check layer.

mod common;

use axum::Router;
use axum::http::StatusCode;
use bauth_axum::csrf::CsrfConfig;
use bauth_axum::dto::AuthResponse;
use common::{SignupClient, TestApp};
use reqwest::header;
use url::Url;

const APP_ORIGIN: &str = "https://app.test";
const EVIL_ORIGIN: &str = "https://evil.test";

async fn start(csrf_config: Option<CsrfConfig>) -> TestApp {
    TestApp::start_with(Router::new(), false, |builder| {
        let builder = builder.external_origin(Url::parse(APP_ORIGIN).expect("origin"));
        if let Some(config) = csrf_config {
            builder.with_csrf(config)
        } else {
            builder
        }
    })
    .await
}

fn cookie_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("client")
}

async fn login(client: &reqwest::Client, app: &TestApp, email: &str) -> AuthResponse {
    SignupClient::new(app).signup(client, app, email).await
}

#[tokio::test]
async fn same_origin_post_with_cookie_passes() {
    let app = start(None).await;
    let client = cookie_client();
    let issued = login(&client, &app, "same-origin@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, APP_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let me = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn cross_origin_post_with_cookie_is_rejected() {
    let app = start(None).await;
    let client = cookie_client();
    let issued = login(&client, &app, "cross-origin@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "csrf_origin_mismatch");

    let me = client.get(app.url("/me")).send().await.expect("me");
    assert_eq!(me.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn get_with_cookie_is_unaffected() {
    let app = start(None).await;
    let client = cookie_client();
    let _ = login(&client, &app, "get@example.com").await;

    let resp = client
        .get(app.url("/me"))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("me");
    assert_eq!(resp.status(), StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn bearer_request_is_unaffected_even_with_cookie() {
    let app = start(None).await;
    let client = cookie_client();
    let issued = login(&client, &app, "bearer@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .bearer_auth(&issued.token)
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_mode_allows_cross_origin_post_with_cookie() {
    let app = start(Some(CsrfConfig::disabled())).await;
    let client = cookie_client();
    let issued = login(&client, &app, "disabled@example.com").await;

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", issued.session.id)))
        .header(header::ORIGIN, EVIL_ORIGIN)
        .send()
        .await
        .expect("delete");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}
