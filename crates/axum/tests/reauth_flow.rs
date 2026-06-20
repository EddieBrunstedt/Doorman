//! HTTP tests for the re-authentication dance fronting the destructive
//! `/auth` routes: the `401 reauth_required` → `/auth/reauth/start` →
//! assertion → retry-succeeds recipe, plus the disabled-policy passthrough.

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{SignupClient, TestApp};
use doorman_axum::dto::{DeleteAccountRequest, RemovePasskeyRequest};
use doorman_core::reauth::{ReauthAction, ReauthPolicy};
use serde_json::Value;

/// Start an app that gates the three destructive actions behind re-auth.
async fn gated_app() -> TestApp {
    TestApp::start_with(Router::new(), false, |b| {
        b.reauthentication(ReauthPolicy::required_for([
            ReauthAction::DeleteAccount,
            ReauthAction::RequestEmailChange,
            ReauthAction::RemovePasskey,
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

    // 1. Proof-less delete is refused with 401 + a machine-readable code.
    let resp = client
        .delete(app.url("/auth/account"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("delete without proof");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "reauth_required");

    // The account is untouched: the bearer still resolves.
    let still_there = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me");
    assert_eq!(still_there.status(), StatusCode::OK);

    // 2. Run the ceremony and 3. retry with the proof → success.
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

    // The account is gone: the session no longer resolves.
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
    // A second credential on a distinct authenticator, so removing one does not
    // strip the last passkey and the reauth ceremony still has a key to assert.
    let mut second = SignupClient::new(&app);
    let extra = second
        .register_additional_passkey(&client, &app, &auth.token)
        .await;

    // Proof-less removal is refused.
    let resp = client
        .delete(app.url(&format!("/auth/passkey/{}", extra.credential_id)))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("remove without proof");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("error body");
    assert_eq!(body["error"]["code"], "reauth_required");

    // With a fresh proof it succeeds.
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
async fn disabled_policy_lets_delete_through_without_proof() {
    // The default `TestApp` wires `ReauthPolicy::disabled()`, so the proof-less
    // delete succeeds — the gate is genuinely off, not merely lenient.
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
