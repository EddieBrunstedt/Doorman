use axum::http::{Method, StatusCode};
use doorman_axum::dto::{PasskeyAuthenticateFinishRequest, PasskeyChallenge, SessionDto};
use doorman_core::session::SessionConfig;
use doorman_core::storage::SessionTransport;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::common::{Client, Reply, ResidentAuthenticator, TestApp, rp_origin};

#[derive(Debug, Clone, Copy)]
enum SessionStart {
    Login,
    Signup,
    Recovery,
}

const STARTS: [SessionStart; 3] = [
    SessionStart::Login,
    SessionStart::Signup,
    SessionStart::Recovery,
];

async fn start(
    app: &TestApp,
    start: SessionStart,
    client: Client,
    transport: Option<SessionTransport>,
) -> Reply {
    match start {
        SessionStart::Login => {
            let (_, mut authenticator) = app.signup("alice@example.com").await;
            let credential_id = authenticator.credential_ids()[0].clone();
            app.log_in_asking(client, transport, &mut authenticator, &credential_id)
                .await
        }
        SessionStart::Signup => {
            let mut authenticator = ResidentAuthenticator::new(&rp_origin());
            app.finish_signup_asking(client, transport, "alice@example.com", &mut authenticator)
                .await
        }
        SessionStart::Recovery => {
            app.signup("alice@example.com").await;
            let mut authenticator = ResidentAuthenticator::new(&rp_origin());
            app.finish_recovery_asking(client, transport, "alice@example.com", &mut authenticator)
                .await
        }
    }
}

#[tokio::test]
async fn every_session_start_hands_its_token_out_only_by_its_transport() {
    for session_start in STARTS {
        for client in [Client::Browser, Client::Bearer] {
            let app = TestApp::new();

            let reply = start(&app, session_start, client, client.requested_transport()).await;

            let case = format!("{session_start:?} {client:?}");
            assert_eq!(reply.status, StatusCode::OK, "{case}");
            let session = reply.session(client);
            assert_eq!(session.session.transport, client.transport(), "{case}");
            assert!(app.is_authenticated(&session).await, "{case}");
        }
    }
}

#[tokio::test]
async fn a_token_presented_the_other_way_is_no_session() {
    let app = TestApp::new();
    let browser = app.session_as(Client::Browser, "alice@example.com").await;
    let bearer = app.session_as(Client::Bearer, "bob@example.com").await;

    let browser_token_as_bearer = app.get("/me").bearer(&browser.token).send().await;
    let bearer_token_as_cookie = app.get("/me").cookie(&bearer.token).send().await;

    for reply in [browser_token_as_bearer, bearer_token_as_cookie] {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.error_code(), "session_not_found");
    }
}

#[tokio::test]
async fn a_browser_cannot_start_a_bearer_session() {
    for session_start in STARTS {
        let app = TestApp::new();

        let reply = start(
            &app,
            session_start,
            Client::Browser,
            Some(SessionTransport::Bearer),
        )
        .await;

        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{session_start:?}");
        assert_eq!(
            reply.error_code(),
            "bearer_session_not_allowed",
            "{session_start:?}"
        );
        assert!(reply.set_cookie().is_none(), "{session_start:?}");
    }
}

#[tokio::test]
async fn a_refused_bearer_login_from_a_browser_leaves_its_challenge_for_a_cookie_session() {
    let app = TestApp::new();
    let (_, mut authenticator) = app.signup("alice@example.com").await;
    let credential_id = authenticator.credential_ids()[0].clone();
    let started = app
        .post("/auth/passkey/authenticate/start")
        .sent_from_page()
        .send()
        .await;
    let challenge: PasskeyChallenge<RequestChallengeResponse> = started.json();
    let mut finish = |transport| PasskeyAuthenticateFinishRequest {
        challenge_id: challenge.challenge_id.clone(),
        response: authenticator.do_authentication(challenge.options.clone(), &credential_id),
        transport,
    };
    let as_bearer = finish(Some(SessionTransport::Bearer));
    let as_cookie = finish(None);

    let refused = app
        .post("/auth/passkey/authenticate/finish")
        .header("origin", crate::common::RP_ORIGIN)
        .json(&as_bearer)
        .send()
        .await;
    let accepted = app
        .post("/auth/passkey/authenticate/finish")
        .sent_from_page()
        .json(&as_cookie)
        .send()
        .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error_code(), "bearer_session_not_allowed");
    assert_eq!(accepted.status, StatusCode::OK);
    accepted.session(Client::Browser);
}

#[tokio::test]
async fn a_request_carrying_both_credentials_is_refused() {
    let app = TestApp::new();
    let browser = app.session_as(Client::Browser, "alice@example.com").await;
    let bearer = app.session_as(Client::Bearer, "bob@example.com").await;

    for (method, path) in [(Method::GET, "/me"), (Method::POST, "/auth/logout")] {
        let reply = app
            .call(method.clone(), path)
            .cookie(&browser.token)
            .bearer(&bearer.token)
            .send()
            .await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert_eq!(
            reply.error_code(),
            "ambiguous_credential",
            "{method} {path}"
        );
    }
    assert!(app.is_authenticated(&browser).await);
    assert!(app.is_authenticated(&bearer).await);
}

#[tokio::test]
async fn without_bearer_sessions_the_authorization_header_is_left_to_the_host() {
    let app = TestApp::with(|b| b.session(SessionConfig::default()), |b| b);
    let browser = app.session_as(Client::Browser, "alice@example.com").await;

    let mut authenticator = ResidentAuthenticator::new(&rp_origin());
    let bearer_signup = app
        .finish_signup(Client::Bearer, "bob@example.com", &mut authenticator)
        .await;
    let me = app
        .get("/me")
        .cookie(&browser.token)
        .header("authorization", "Bearer the-hosts-own-api-key")
        .send()
        .await;

    assert_eq!(bearer_signup.status, StatusCode::FORBIDDEN);
    assert_eq!(bearer_signup.error_code(), "bearer_session_not_allowed");
    assert_eq!(me.status, StatusCode::OK);
}

#[tokio::test]
async fn ending_a_bearer_session_sets_no_cookie() {
    for (method, path) in [
        (Method::POST, "/auth/logout"),
        (Method::POST, "/auth/logout-all"),
        (Method::DELETE, "/auth/user"),
        (Method::DELETE, "/auth/sessions/{current}"),
    ] {
        let app = TestApp::new();
        let session = app.session_for("alice@example.com").await;
        let target = path.replace("{current}", &session.session.id.0.to_string());

        let reply = app
            .call(method.clone(), &target)
            .session(&session)
            .send()
            .await;

        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{method} {path}");
        assert!(reply.set_cookie().is_none(), "{method} {path}");
        assert!(!app.is_authenticated(&session).await, "{method} {path}");
    }
}

#[tokio::test]
async fn the_session_list_names_each_sessions_transport() {
    let app = TestApp::new();
    let browser = app.session_as(Client::Browser, "alice@example.com").await;
    let bearer = app.session_as(Client::Bearer, "alice@example.com").await;

    let listed: Vec<SessionDto> = app
        .get("/auth/sessions")
        .session(&bearer)
        .send()
        .await
        .json();

    let transport_of = |id| {
        listed
            .iter()
            .find(|session| session.id == id)
            .map(|session| session.transport)
    };
    assert_eq!(
        transport_of(browser.session.id),
        Some(SessionTransport::Cookie)
    );
    assert_eq!(
        transport_of(bearer.session.id),
        Some(SessionTransport::Bearer)
    );
}
