//! Over HTTP, a session revoked through the framework-agnostic managers stops
//! authenticating on the very next request, even right after a request warmed
//! the resolver's cache. Proves `AuthService::builder` wires the session layer
//! to the resolver whose invalidator the managers fire; the eviction itself is
//! covered in core (`resolve_flow.rs`).

mod common;

use axum::Router;
use axum::http::StatusCode;
use common::{TestApp, login};
use doorman_core::audit::OperatorActor;

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
async fn revoked_session_is_unauthorized_on_the_next_request() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();
    let auth = login(&client, &app, "alice@example.com").await;
    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);

    app.session_manager
        .revoke(&auth.token)
        .await
        .expect("revoke");
    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::UNAUTHORIZED
    );

    app.shutdown().await;
}

#[tokio::test]
async fn operator_deleted_account_is_unauthorized_on_the_next_request() {
    let app = TestApp::start(Router::new(), false).await;
    let client = reqwest::Client::new();
    let auth = login(&client, &app, "doomed@example.com").await;
    assert_eq!(me(&client, &app, &auth.token).await, StatusCode::OK);

    let actor = OperatorActor::new("incident-responder", None, None, None)
        .expect("operator actor within bounds");
    app.operator
        .delete_account(auth.user.id, actor)
        .await
        .expect("operator delete");
    assert_eq!(
        me(&client, &app, &auth.token).await,
        StatusCode::UNAUTHORIZED
    );

    app.shutdown().await;
}
