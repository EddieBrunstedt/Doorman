use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use crate::common::ResidentHttpAuthenticator;
use axum::http::StatusCode;
use axum::{Router, routing::get};
use doorman_axum::dto::{
    AuthResponse, PasskeyChallenge, RecoveryRedeemRequest, RecoveryRequest,
    RegistrationFinishRequest, SignupRedeemRequest, SignupRequest,
};
use doorman_axum::prelude::*;
use doorman_core::email_link::TOKEN_PLACEHOLDER;
use doorman_core::memory::InMemoryRateLimiter;
use doorman_sqlx::SqliteStorage;
use doorman_test_support::CapturingEmailSender;
use tokio::net::TcpListener;
use url::Url;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const ORIGIN: &str = "http://localhost:3000";
const SIGNUP_TEMPLATE: &str = "http://localhost:3000/signup?token={token}";
const RECOVERY_TEMPLATE: &str = "http://localhost:3000/recovery?token={token}";

#[tokio::test]
async fn signup_login_recovery_round_trip() {
    async fn me(AuthUser(user): AuthUser) -> String {
        user.email.unwrap_or_else(|| "unknown".to_owned())
    }

    let storage = SqliteStorage::connect("sqlite::memory:")
        .await
        .expect("connect");
    storage.migrate().await.expect("migrate");

    let email = Arc::new(CapturingEmailSender::new());
    let origin: Url = ORIGIN.parse().expect("origin");
    let base = origin.as_str().trim_end_matches('/');
    let core = AuthCore::builder(storage.all_stores())
        .email(email.clone() as Arc<dyn doorman_core::email::EmailSender>)
        .passkey(PasskeyConfig::new("localhost", origin.clone(), "Example"))
        .reauthentication(ReauthPolicy::disabled())
        .audit(Arc::new(NoopAuditSink))
        .limiter(Arc::new(InMemoryRateLimiter::new(Arc::new(SystemClock))))
        .signup(SignupConfig {
            url_template: format!("{base}/signup?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .recovery(RecoveryConfig {
            url_template: format!("{base}/recovery?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .user(UserConfig {
            url_template: format!("{base}/user/email?token={TOKEN_PLACEHOLDER}"),
            ..Default::default()
        })
        .build()
        .expect("auth core built");
    let auth = AuthService::builder(core)
        .external_origin(origin.clone())
        .cookie(CookieConfig::default())
        .build()
        .expect("auth built");

    let app = Router::new()
        .merge(auth.router())
        .route("/api/me", get(me))
        .layer(auth.session_layer());

    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .expect("serve");
    });

    let client = reqwest::Client::new();
    let url = |path: &str| format!("http://{addr}{path}");
    let mut authenticator = ResidentHttpAuthenticator::new(&origin);

    let request = client
        .post(url("/auth/signup/request"))
        .json(&SignupRequest {
            email: "alice@example.com".into(),
            invite_token: None,
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

    let redeem = client
        .post(url("/auth/signup/redeem"))
        .json(&SignupRedeemRequest {
            token: signup_token,
        })
        .send()
        .await
        .expect("signup redeem");
    assert_eq!(redeem.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        redeem.json().await.expect("redeem body");

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
    assert_eq!(logged_in.user.id, signed_up.user.id, "same user");

    let me = client
        .get(url("/api/me"))
        .bearer_auth(&logged_in.token)
        .send()
        .await
        .expect("me");
    assert_eq!(me.status(), StatusCode::OK);
    assert_eq!(me.text().await.expect("me body"), "alice@example.com");

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
            .find(|m| m.subject == "Recover access with a new passkey")
            .expect("recovery link queued")
            .body_text
            .clone();
        doorman_test_support::token_from_email(&body, RECOVERY_TEMPLATE)
    };

    let redeem = client
        .post(url("/auth/recovery/redeem"))
        .json(&RecoveryRedeemRequest {
            token: recovery_token,
        })
        .send()
        .await
        .expect("recovery redeem");
    assert_eq!(redeem.status(), StatusCode::OK);
    let challenge: PasskeyChallenge<CreationChallengeResponse> =
        redeem.json().await.expect("recovery redeem body");

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
        "recovered the same user"
    );

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
