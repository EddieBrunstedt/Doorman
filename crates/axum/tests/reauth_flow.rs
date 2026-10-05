mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{SignupClient, TestApp};
use doorman_axum::dto::{DeleteAccountRequest, RemovePasskeyRequest, RevokeSessionRequest};
use doorman_core::reauth::{ReauthAction, ReauthPolicy};
use serde_json::Value;

async fn gated_app() -> TestApp {
    TestApp::start_with(Router::new(), false, |b| {
        b.reauthentication(ReauthPolicy::required_for([
            ReauthAction::DeleteAccount,
            ReauthAction::RequestEmailChange,
            ReauthAction::RemovePasskey,
            ReauthAction::RevokeOtherSessions,
            ReauthAction::RevokeSession,
        ]))
    })
    .await
}

#[tokio::test]
async fn delete_account_runs_the_full_reauth_dance() {
    let app = gated_app().await;
    let client = reqwest::Client::new();
    let mut signup = SignupClient::new(&app);
    let auth = signup.signup(&client, &app, "owner@example.com").await;

    let resp = client
        .delete(app.url("/auth/account"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete without proof");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "reauth_required");

    let still_there = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me");
    assert_eq!(still_there.status(), StatusCode::OK);

    let proof = signup.reauth(&client, &app, &auth.token).await;
    let resp = client
        .delete(app.url("/auth/account"))
        .bearer_auth(&auth.token)
        .json(&DeleteAccountRequest {
            reauthentication: Some(proof),
        })
        .send()
        .await
        .expect("delete with proof");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let gone = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me after delete");
    assert_eq!(gone.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}

#[tokio::test]
async fn remove_passkey_runs_the_full_reauth_dance() {
    let app = gated_app().await;
    let client = reqwest::Client::new();
    let mut signup = SignupClient::new(&app);
    let auth = signup.signup(&client, &app, "owner@example.com").await;
    let mut second = SignupClient::new(&app);
    let extra = second
        .register_additional_passkey(&client, &app, &auth.token)
        .await;

    let resp = client
        .delete(app.url(&format!("/auth/passkey/{}", extra.credential_id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("remove without proof");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "reauth_required");

    let proof = signup.reauth(&client, &app, &auth.token).await;
    let resp = client
        .delete(app.url(&format!("/auth/passkey/{}", extra.credential_id)))
        .bearer_auth(&auth.token)
        .json(&RemovePasskeyRequest {
            reauthentication: Some(proof),
        })
        .send()
        .await
        .expect("remove with proof");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn revoke_other_sessions_runs_the_full_reauth_dance() {
    let app = gated_app().await;
    let client = reqwest::Client::new();
    let mut signup = SignupClient::new(&app);
    let auth = signup.signup(&client, &app, "owner@example.com").await;
    let other = common::login(&client, &app, "owner@example.com").await;

    let resp = client
        .delete(app.url("/auth/sessions"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("revoke others without proof");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "reauth_required");

    let proof = signup.reauth(&client, &app, &auth.token).await;
    let resp = client
        .delete(app.url("/auth/sessions"))
        .bearer_auth(&auth.token)
        .json(&RevokeSessionRequest {
            reauthentication: Some(proof),
        })
        .send()
        .await
        .expect("revoke others with proof");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let gone = client
        .get(app.url("/me"))
        .bearer_auth(&other.token)
        .send()
        .await
        .expect("me with revoked session");
    assert_eq!(gone.status(), StatusCode::UNAUTHORIZED);

    let resp = client
        .delete(app.url(&format!("/auth/sessions/{}", auth.session.id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("revoke current session");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_policy_lets_delete_through_without_proof() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();
    let mut signup = SignupClient::new(&app);
    let auth = signup.signup(&client, &app, "owner@example.com").await;

    let resp = client
        .delete(app.url("/auth/account"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete without proof");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    app.shutdown().await;
}

#[tokio::test]
async fn reauth_start_requires_authentication() {
    let app = gated_app().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(app.url("/auth/reauth/start"))
        .send()
        .await
        .expect("anon reauth start");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    app.shutdown().await;
}
