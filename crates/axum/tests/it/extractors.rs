use doorman_axum::AuthSession;

use crate::common::TestApp;

#[tokio::test]
async fn auth_session_debug_redacts_token() {
    let app = TestApp::new();
    let issued = app.session_for("alice@example.com").await;
    let auth = AuthSession {
        session: app.sessions.resolve(&issued.token).await.expect("resolve"),
        token: issued.token.clone(),
    };

    let rendered = format!("{auth:?}");
    assert!(
        !rendered.contains(&issued.token),
        "Debug output leaked the cleartext token: {rendered}"
    );
    assert!(rendered.contains("<redacted>"), "expected redaction marker");
}
