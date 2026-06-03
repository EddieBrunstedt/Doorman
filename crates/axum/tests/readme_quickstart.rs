//! Exercises the README quickstart wiring end to end.
//!
//! The first test pins that the documented snippet still type-checks. The
//! second stands the very same wiring up on a real socket and drives a full
//! signup -> passkey login -> recovery round trip against it, so the
//! quickstart is verified to *work*, not merely to compile. The only
//! departure from the literal snippet is swapping the terminal email sender
//! for a capturing one, so the test can read the verification links the
//! flows mail out.

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::http::StatusCode;
use axum::{Router, routing::get};
use common::ResidentHttpAuthenticator;
use doorman_axum::dto::{
    AuthResponse, PasskeyChallenge, RecoveryConsumeRequest, RecoveryRequest,
    RegistrationFinishRequest, SignupConsumeRequest, SignupRequest,
};
use doorman_axum::prelude::*;
use doorman_core::verification::TOKEN_PLACEHOLDER;
use doorman_sqlx::SqliteStorage;
use doorman_test_support::CapturingEmailSender;
use tokio::net::TcpListener;
use url::Url;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

#[tokio::test]
async fn readme_quickstart_snippet_compiles() -> std::result::Result<(), Box<dyn std::error::Error>>
{
    async fn me(auth: AuthSession) -> String {
        auth.user
            .email
            .clone()
            .unwrap_or_else(|| "unknown".to_owned())
    }

    let storage = SqliteStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;
    let origin: Url = "http://localhost:3000".parse()?;
    let base = origin.as_str().trim_end_matches('/');
    let auth = AuthService::builder(storage.all_stores())
        .email(Arc::new(TerminalEmailSender))
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .signup(SignupConfig {
            url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .external_origin(origin)
        .cookie(CookieConfig::default())
        .build()?;
    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(me))
        .layer(auth.session_layer());
    let _ = app;
    Ok(())
}

/// The relying-party origin the quickstart configures. The WebAuthn
/// authenticator signs against this; HTTP requests go to the bound address.
const ORIGIN: &str = "http://localhost:3000";
const SIGNUP_TEMPLATE: &str = "http://localhost:3000/signup?token={token}";
const RECOVERY_TEMPLATE: &str = "http://localhost:3000/recovery?token={token}";

#[tokio::test]
async fn readme_quickstart_drives_signup_login_recovery() {
    async fn me(auth: AuthSession) -> String {
        auth.user
            .email
            .clone()
            .unwrap_or_else(|| "unknown".to_owned())
    }

    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let email = Arc::new(CapturingEmailSender::new());
    let origin: Url = ORIGIN.parse().expect("origin");
    let base = origin.as_str().trim_end_matches('/');
    let auth = AuthService::builder(storage.all_stores())
        .email(email.clone() as Arc<dyn doorman_core::email::EmailSender>)
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .signup(SignupConfig {
            url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .external_origin(origin.clone())
        .cookie(CookieConfig::default())
        .silence_warnings()
        .build()
        .expect("auth built");

    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(me))
        .layer(auth.session_layer());

    // Stand the app up on an ephemeral port.
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve");
    });

    // A non-cookie client: every authenticated call uses a bearer token, so
    // no session cookie is ever sent and the CSRF layer (which only guards
    // cookie-backed requests) stays out of the way.
    let client = reqwest::Client::new();
    let url = |path: &str| format!("http://{addr}{path}");
    // The authenticator signs against the configured origin, not the bound
    // address — that is what WebAuthn verification checks.
    let mut authenticator = ResidentHttpAuthenticator::new(&origin);

    // --- Signup ---
    let request = client
        .post(url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("signup request");
    assert_eq!(request.status(), StatusCode::NO_CONTENT);

    let signup_token = {
        let sent = email.sent();
        let body = &sent.last().expect("signup email queued").body_text;
        doorman_test_support::token_from_email(body, SIGNUP_TEMPLATE)
    };

    let consume = client
        .post(url("/auth/signup/consume"))
        .json(&SignupConsumeRequest {
            token: signup_token,
        })
        .send()
        .await
        .expect("signup consume");
    assert_eq!(consume.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        consume.json().await.expect("consume body");

    let attestation = authenticator.do_registration(challenge.options);
    let login_credential_id = attestation.raw_id.as_ref().to_vec();
    let finish = client
        .post(url("/auth/signup/finish"))
        .json(&RegistrationFinishRequest {
            challenge_id: challenge.challenge_id,
            response: attestation,
            name: Some("primary device".into()),
        })
        .send()
        .await
        .expect("signup finish");
    assert_eq!(finish.status(), StatusCode::OK);
    let signed_up: AuthResponse = finish.json().await.expect("finish body");
    assert!(!signed_up.token.is_empty(), "signup issued a session token");

    // --- Login with the freshly registered passkey (discoverable auth) ---
    let start = client
        .post(url("/auth/passkey/authenticate/start"))
        .send()
        .await
        .expect("authenticate start");
    assert_eq!(start.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<RequestChallengeResponse> =
        start.json().await.expect("authenticate start body");
    let assertion = authenticator.do_authentication(challenge.options, &login_credential_id);
    let finish = client
        .post(url("/auth/passkey/authenticate/finish"))
        .json(&serde_json::json!({
            "challenge_id": challenge.challenge_id,
            "response": assertion,
        }))
        .send()
        .await
        .expect("authenticate finish");
    assert_eq!(finish.status(), StatusCode::OK);
    let logged_in: AuthResponse = finish.json().await.expect("authenticate finish body");
    assert_eq!(logged_in.user.id, signed_up.user.id, "same account");

    // The login session resolves on a protected route.
    let me = client
        .get(url("/api/me"))
        .bearer_auth(&logged_in.token)
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(me.text().await.expect("me body"), "alice@example.com");

    // --- Recovery: enrol a new passkey via the emailed link ---
    let request = client
        .post(url("/auth/recovery/request"))
        .json(&RecoveryRequest {
            email: "alice@example.com".into(),
        })
        .send()
        .await
        .expect("recovery request");
    assert_eq!(request.status(), StatusCode::NO_CONTENT);

    let recovery_token = {
        let sent = email.sent();
        let body = sent
            .iter()
            .rev()
            .find(|m| m.subject == "Recover access to your account")
            .expect("recovery link queued")
            .body_text
            .clone();
        doorman_test_support::token_from_email(&body, RECOVERY_TEMPLATE)
    };

    let consume = client
        .post(url("/auth/recovery/consume"))
        .json(&RecoveryConsumeRequest {
            token: recovery_token,
        })
        .send()
        .await
        .expect("recovery consume");
    assert_eq!(consume.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        consume.json().await.expect("recovery consume body");

    let attestation = authenticator.do_registration(challenge.options);
    let finish = client
        .post(url("/auth/recovery/finish"))
        .json(&RegistrationFinishRequest {
            challenge_id: challenge.challenge_id,
            response: attestation,
            name: Some("recovery device".into()),
        })
        .send()
        .await
        .expect("recovery finish");
    assert_eq!(finish.status(), StatusCode::OK);
    let recovered: AuthResponse = finish.json().await.expect("recovery finish body");
    assert_eq!(
        recovered.user.id, signed_up.user.id,
        "recovered same account"
    );

    // The recovery session is usable too.
    let me = client
        .get(url("/api/me"))
        .bearer_auth(&recovered.token)
        .send()
        .await
        .expect("me after recovery");
    assert_eq!(me.status(), StatusCode::OK);

    let _ = shutdown_tx.send(());
    let _ = server.await;
}
