use axum::http::{Method, StatusCode};
use doorman_axum::dto::{PasskeyDto, Reauthentication};
use doorman_core::reauth::{ReauthAction, ReauthPolicy};
use serde_json::{Value, json};

use crate::common::{ResidentAuthenticator, TestApp, rp_origin};

#[tokio::test]
async fn every_session_route_refuses_a_request_without_a_session() {
    let app = TestApp::new();
    let some_id = "00000000-0000-4000-8000-000000000000";
    let routes = [
        (Method::POST, "/auth/logout".to_owned()),
        (Method::POST, "/auth/logout-all".to_owned()),
        (Method::GET, "/auth/sessions".to_owned()),
        (Method::DELETE, "/auth/sessions".to_owned()),
        (Method::DELETE, format!("/auth/sessions/{some_id}")),
        (Method::POST, "/auth/passkey/register/start".to_owned()),
        (Method::POST, "/auth/passkey/register/finish".to_owned()),
        (Method::GET, "/auth/passkey".to_owned()),
        (Method::DELETE, "/auth/passkey/some-passkey".to_owned()),
        (Method::PATCH, "/auth/passkey/some-passkey".to_owned()),
        (Method::POST, "/auth/reauth/start".to_owned()),
        (Method::POST, "/auth/user/email".to_owned()),
        (Method::DELETE, "/auth/user".to_owned()),
    ];

    for (method, path) in routes {
        let reply = app
            .call(method.clone(), &path)
            .json(&json!({}))
            .send()
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(reply.error_code(), "session_not_found", "{method} {path}");
    }
}

#[tokio::test]
async fn a_session_id_that_is_malformed_or_another_users_is_not_found() {
    let app = TestApp::new();
    let alice = app.session_for("alice@example.com").await;
    let bob = app.session_for("bob@example.com").await;

    for id in ["not-a-uuid".to_owned(), bob.session.id.to_string()] {
        let reply = app
            .delete(&format!("/auth/sessions/{id}"))
            .bearer(&alice.token)
            .send()
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{id}");
        assert_eq!(reply.error_code(), "session_not_found", "{id}");
    }
    assert!(app.is_authenticated(&bob).await);
}

#[tokio::test]
async fn destructive_routes_refuse_a_session_in_recovery_cool_down() {
    let app = TestApp::new();
    let (signed_up, _) = app.signup("alice@example.com").await;
    let mut authenticator = ResidentAuthenticator::new(&rp_origin());
    let recovered = app.recover("alice@example.com", &mut authenticator).await;
    let passkeys: Vec<PasskeyDto> = app
        .get("/auth/passkey")
        .bearer(&recovered.token)
        .send()
        .await
        .json();

    let routes = [
        (
            Method::DELETE,
            format!("/auth/passkey/{}", passkeys[0].credential_id),
            json!({}),
        ),
        (
            Method::DELETE,
            format!("/auth/sessions/{}", signed_up.session.id),
            json!({}),
        ),
        (Method::DELETE, "/auth/sessions".to_owned(), json!({})),
        (Method::POST, "/auth/logout-all".to_owned(), json!({})),
        (
            Method::POST,
            "/auth/user/email".to_owned(),
            json!({ "new_email": "new@example.com" }),
        ),
        (Method::DELETE, "/auth/user".to_owned(), json!({})),
    ];

    for (method, path, body) in routes {
        let reply = app
            .call(method.clone(), &path)
            .bearer(&recovered.token)
            .json(&body)
            .send()
            .await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{method} {path}");
        assert_eq!(
            reply.error_code(),
            "recovery_cool_down_active",
            "{method} {path}"
        );
    }
    assert!(app.is_authenticated(&signed_up).await);
}

#[tokio::test]
async fn deleting_the_acting_session_logs_out_without_a_gate() {
    for in_cool_down in [false, true] {
        let app = TestApp::with(
            |b| {
                b.reauthentication(ReauthPolicy::required_for([
                    ReauthAction::RevokeAnotherSession,
                ]))
            },
            |b| b,
        );
        let (signed_up, _) = app.signup("alice@example.com").await;
        let acting = if in_cool_down {
            let mut authenticator = ResidentAuthenticator::new(&rp_origin());
            app.recover("alice@example.com", &mut authenticator).await
        } else {
            signed_up.clone()
        };

        let reply = app
            .delete(&format!("/auth/sessions/{}", acting.session.id))
            .bearer(&acting.token)
            .send()
            .await;

        assert_eq!(
            reply.status,
            StatusCode::NO_CONTENT,
            "in cool-down: {in_cool_down}"
        );
        assert!(
            !app.is_authenticated(&acting).await,
            "in cool-down: {in_cool_down}"
        );
    }
}

#[derive(Debug, Clone, Copy)]
enum Gated {
    DeleteUser,
    RemovePasskey,
    RevokeAnotherSession,
    RevokeOtherSessions,
    LogOutEverywhere,
    RequestEmailChange,
}

#[tokio::test]
async fn gated_routes_require_and_accept_a_reauthentication() {
    for gated in [
        Gated::DeleteUser,
        Gated::RemovePasskey,
        Gated::RevokeAnotherSession,
        Gated::RevokeOtherSessions,
        Gated::LogOutEverywhere,
        Gated::RequestEmailChange,
    ] {
        let app = TestApp::with(
            |b| {
                b.reauthentication(ReauthPolicy::required_for([
                    ReauthAction::DeleteUser,
                    ReauthAction::RemovePasskey,
                    ReauthAction::RevokeAnotherSession,
                    ReauthAction::RevokeOtherSessions,
                    ReauthAction::RequestEmailChange,
                ]))
            },
            |b| b,
        );
        let (auth, mut authenticator) = app.signup("owner@example.com").await;
        let other = app.log_in_again(&mut authenticator).await;
        let (method, path) = match gated {
            Gated::DeleteUser => (Method::DELETE, "/auth/user".to_owned()),
            Gated::RemovePasskey => {
                let mut backup = ResidentAuthenticator::new(&rp_origin());
                let extra = app.register_passkey(&mut backup, &auth).await;
                (
                    Method::DELETE,
                    format!("/auth/passkey/{}", extra.credential_id),
                )
            }
            Gated::RevokeAnotherSession => (
                Method::DELETE,
                format!("/auth/sessions/{}", other.session.id),
            ),
            Gated::RevokeOtherSessions => (Method::DELETE, "/auth/sessions".to_owned()),
            Gated::LogOutEverywhere => (Method::POST, "/auth/logout-all".to_owned()),
            Gated::RequestEmailChange => (Method::POST, "/auth/user/email".to_owned()),
        };
        let body = |proof: Option<Reauthentication>| {
            let mut body = json!({ "reauthentication": proof });
            if let Gated::RequestEmailChange = gated {
                body["new_email"] = Value::from("new@example.com");
            }
            body
        };

        let refused = app
            .call(method.clone(), &path)
            .bearer(&auth.token)
            .json(&body(None))
            .send()
            .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{gated:?}");
        assert_eq!(refused.error_code(), "reauth_required", "{gated:?}");

        let proof = app.reauth(&mut authenticator, &auth).await;
        let accepted = app
            .call(method, &path)
            .bearer(&auth.token)
            .json(&body(Some(proof)))
            .send()
            .await;
        assert_eq!(accepted.status, StatusCode::NO_CONTENT, "{gated:?}");
    }
}
