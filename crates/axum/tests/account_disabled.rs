mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{ResidentHttpAuthenticator, TestApp, login};
use doorman_axum::dto::PasskeyChallenge;
use doorman_core::audit::OperatorActor;
use doorman_core::storage::AccountStatus;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

fn operator() -> OperatorActor {
    OperatorActor::new("support-agent-7", None, None, None).expect("operator actor")
}

async fn me(client: &reqwest::Client, app: &TestApp, token: &str) -> StatusCode {
    client
        .get(app.url("/me"))
        .bearer_auth(token)
        .send()
        .await
        .expect("me")
        .status()
}

#[tokio::test]
async fn disabled_user_is_refused_with_403() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "disabled@example.com").await;
    app.set_user_status(
        auth.user.id,
        AccountStatus::Disabled {
            at: chrono::Utc::now(),
        },
    )
    .await;

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::FORBIDDEN,
        "a disabled account is refused, not served"
    );

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_response_carries_stable_code() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "coded@example.com").await;
    app.set_user_status(
        auth.user.id,
        AccountStatus::Disabled {
            at: chrono::Utc::now(),
        },
    )
    .await;

    let response = client
        .get(app.url("/me"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("me");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "account_disabled");

    app.shutdown().await;
}

#[tokio::test]
async fn active_user_is_unaffected() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "active@example.com").await;

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::OK,
        "an active user still authenticates"
    );

    app.set_user_status(auth.user.id, AccountStatus::Active)
        .await;
    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);

    app.shutdown().await;
}

#[tokio::test]
async fn operator_disable_locks_out_live_session_then_enable_restores() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();

    let auth = login(&client, &app, "locked@example.com").await;

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::OK,
        "an active user authenticates",
    );

    app.operator
        .disable(auth.user.id, operator())
        .await
        .expect("operator disable");

    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::UNAUTHORIZED,
        "the revoked session no longer resolves after disable",
    );

    app.operator
        .enable(auth.user.id, operator())
        .await
        .expect("operator enable");

    let reauth = login(&client, &app, "locked@example.com").await;
    assert_eq!(
        me(&client, &app, &reauth.token).await,
        StatusCode::OK,
        "a re-enabled account can authenticate a fresh session",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn disabled_user_cannot_log_in() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();
    let mut authenticator = ResidentHttpAuthenticator::new(&app.rp_origin);

    let auth = login(&client, &app, "frozen@example.com").await;

    let start = client
        .post(app.url("/auth/passkey/register/start"))
        .bearer_auth(&auth.token)
        .send()
        .await
        .expect("register start");
    assert_eq!(start.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        start.json().await.expect("register start body");
    let attestation = authenticator.do_registration(challenge.options);
    let credential_id = attestation.raw_id.as_ref().to_vec();
    let finish = client
        .post(app.url("/auth/passkey/register/finish"))
        .bearer_auth(&auth.token)
        .json(&serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "response": attestation,
        }))
        .send()
        .await
        .expect("register finish");
    assert_eq!(finish.status(), StatusCode::OK);

    app.set_user_status(
        auth.user.id,
        AccountStatus::Disabled {
            at: chrono::Utc::now(),
        },
    )
    .await;

    let start = client
        .post(app.url("/auth/passkey/authenticate/start"))
        .send()
        .await
        .expect("authenticate start");
    assert_eq!(start.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<RequestChallengeResponse> =
        start.json().await.expect("authenticate start body");
    let assertion = authenticator.do_authentication(challenge.options, &credential_id);

    let response = client
        .post(app.url("/auth/passkey/authenticate/finish"))
        .json(&serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "response": assertion,
        }))
        .send()
        .await
        .expect("authenticate finish");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .is_none(),
        "a refused login sets no session cookie"
    );
    let body: serde_json::Value = response.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "account_disabled");

    app.shutdown().await;
}
