use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use doorman_axum::dto::{PasskeyAuthenticateFinishRequest, PasskeyChallenge, SessionDto};
use doorman_core::session::SessionConfig;
use doorman_core::storage::SessionTransport;
use webauthn_rs::prelude::RequestChallengeResponse;

use crate::common::{
    Client, DPOP_ORIGIN, DpopClient, Reply, ResidentAuthenticator, TestApp, harness_core, rp_origin,
};

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

async fn start(app: &TestApp, start: SessionStart, client: Client, asks_dpop: bool) -> Reply {
    match start {
        SessionStart::Login => {
            let (_, mut authenticator) = app.signup("alice@example.com").await;
            let credential_id = authenticator.credential_ids()[0].clone();
            app.log_in_asking(client, asks_dpop, &mut authenticator, &credential_id)
                .await
        }
        SessionStart::Signup => {
            let mut authenticator = ResidentAuthenticator::new(&rp_origin());
            app.finish_signup_asking(client, asks_dpop, "alice@example.com", &mut authenticator)
                .await
        }
        SessionStart::Recovery => {
            app.signup("alice@example.com").await;
            let mut authenticator = ResidentAuthenticator::new(&rp_origin());
            app.finish_recovery_asking(client, asks_dpop, "alice@example.com", &mut authenticator)
                .await
        }
    }
}

fn invalid_proof(reply: &Reply, case: &str) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{case}");
    assert_eq!(reply.error_code(), "invalid_dpop_proof", "{case}");
    assert!(
        reply.headers.contains_key(header::WWW_AUTHENTICATE),
        "{case}: no challenge for a new proof"
    );
}

#[tokio::test]
async fn every_session_start_hands_its_token_out_only_by_its_transport() {
    for session_start in STARTS {
        for client in [Client::Browser, Client::Dpop] {
            let app = TestApp::new();

            let reply = start(&app, session_start, client, client == Client::Dpop).await;

            let case = format!("{session_start:?} {client:?}");
            assert_eq!(reply.status, StatusCode::OK, "{case}");
            let session = reply.session(client);
            let expected = match client {
                Client::Browser => SessionTransport::Cookie,
                Client::Dpop => SessionTransport::Dpop {
                    jkt: session.key().jkt(),
                },
            };
            assert_eq!(session.session.transport, expected, "{case}");
            assert!(app.is_authenticated(&session).await, "{case}");
        }
    }
}

#[tokio::test]
async fn a_token_presented_the_other_way_is_no_session() {
    let app = TestApp::new();
    let browser = app.session_as(Client::Browser, "alice@example.com").await;
    let dpop = app.session_as(Client::Dpop, "bob@example.com").await;
    let some_key = Arc::new(DpopClient::new(DPOP_ORIGIN));

    let browser_token_by_dpop = app.get("/me").dpop(&some_key, &browser.token).send().await;
    let dpop_token_as_cookie = app.get("/me").cookie(&dpop.token).send().await;

    for reply in [browser_token_by_dpop, dpop_token_as_cookie] {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.error_code(), "session_not_found");
    }
}

#[tokio::test]
async fn a_dpop_token_is_no_session_without_a_proof_from_its_key() {
    let app = TestApp::new();
    let session = app.session_for("alice@example.com").await;
    let another_key = Arc::new(DpopClient::new(DPOP_ORIGIN));
    let authorization = format!("DPoP {}", session.token);

    let another_keys_proof = app
        .get("/me")
        .dpop(&another_key, &session.token)
        .send()
        .await;
    assert_eq!(another_keys_proof.status, StatusCode::UNAUTHORIZED);
    assert_eq!(another_keys_proof.error_code(), "session_not_found");

    let proof = |path: &str| {
        session
            .key()
            .proof("GET", path, Some(&session.token), chrono::Utc::now())
    };
    let used = proof("/me");
    let cases = [
        ("without a proof", vec![]),
        (
            "with a proof for another path",
            vec![proof("/auth/sessions")],
        ),
        ("with two proofs", vec![proof("/me"), proof("/me")]),
        ("with a proof used before", vec![used.clone()]),
    ];
    let first = app
        .get("/me")
        .header("authorization", &authorization)
        .header("dpop", &used)
        .send()
        .await;
    assert_eq!(first.status, StatusCode::OK);
    for (case, proofs) in cases {
        let mut call = app.get("/me").header("authorization", &authorization);
        for proof in &proofs {
            call = call.header("dpop", proof);
        }
        invalid_proof(&call.send().await, case);
    }
    assert!(app.is_authenticated(&session).await);
}

#[tokio::test]
async fn a_proof_is_checked_against_the_path_the_client_sent_to_a_nested_router() {
    let app = TestApp::nested_under("/api");
    let session = app.session_for("alice@example.com").await;

    let listed = app.get("/auth/sessions").session(&session).send().await;

    assert_eq!(listed.status, StatusCode::OK);
}

#[tokio::test]
async fn a_dpop_client_still_holding_a_session_starts_another_with_the_same_proof() {
    let app = TestApp::new();
    let (held, mut authenticator) = app.signup("alice@example.com").await;
    let credential_id = authenticator.credential_ids()[0].clone();
    let started = app
        .post("/auth/passkey/authenticate/start")
        .session(&held)
        .send()
        .await;
    let challenge: PasskeyChallenge<RequestChallengeResponse> = started.json();

    let finish = app
        .post("/auth/passkey/authenticate/finish")
        .session(&held)
        .json(&PasskeyAuthenticateFinishRequest {
            challenge_id: challenge.challenge_id,
            response: authenticator.do_authentication(challenge.options, &credential_id),
        })
        .send()
        .await;

    assert_eq!(finish.status, StatusCode::OK);
    let started = finish.session(Client::Dpop);
    assert_ne!(started.session.id, held.session.id);
    assert_eq!(
        started.session.transport,
        SessionTransport::Dpop {
            jkt: held.key().jkt()
        }
    );
    assert!(app.is_authenticated(&started).await);
}

#[tokio::test]
async fn a_browser_cannot_start_a_dpop_session() {
    for session_start in STARTS {
        let app = TestApp::new();

        let reply = start(&app, session_start, Client::Browser, true).await;

        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{session_start:?}");
        assert_eq!(
            reply.error_code(),
            "dpop_session_not_allowed",
            "{session_start:?}"
        );
        assert!(reply.set_cookie().is_none(), "{session_start:?}");
    }
}

#[tokio::test]
async fn a_refused_dpop_login_from_a_browser_leaves_its_challenge_for_a_cookie_session() {
    let app = TestApp::new();
    let (_, mut authenticator) = app.signup("alice@example.com").await;
    let credential_id = authenticator.credential_ids()[0].clone();
    let started = app
        .post("/auth/passkey/authenticate/start")
        .sent_from_page()
        .send()
        .await;
    let challenge: PasskeyChallenge<RequestChallengeResponse> = started.json();
    let mut finish = || PasskeyAuthenticateFinishRequest {
        challenge_id: challenge.challenge_id.clone(),
        response: authenticator.do_authentication(challenge.options.clone(), &credential_id),
    };
    let as_dpop = finish();
    let as_cookie = finish();

    let refused = app
        .post("/auth/passkey/authenticate/finish")
        .header("origin", crate::common::RP_ORIGIN)
        .asking_dpop(true)
        .json(&as_dpop)
        .send()
        .await;
    let accepted = app
        .post("/auth/passkey/authenticate/finish")
        .sent_from_page()
        .json(&as_cookie)
        .send()
        .await;

    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error_code(), "dpop_session_not_allowed");
    assert_eq!(accepted.status, StatusCode::OK);
    accepted.session(Client::Browser);
}

#[tokio::test]
async fn a_request_carrying_both_session_tokens_is_refused() {
    let app = TestApp::new();
    let browser = app.session_as(Client::Browser, "alice@example.com").await;
    let dpop = app.session_as(Client::Dpop, "bob@example.com").await;

    for (method, path) in [(Method::GET, "/me"), (Method::POST, "/auth/logout")] {
        let reply = app
            .call(method.clone(), path)
            .cookie(&browser.token)
            .session(&dpop)
            .send()
            .await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert_eq!(
            reply.error_code(),
            "ambiguous_session_token",
            "{method} {path}"
        );
    }
    assert!(app.is_authenticated(&browser).await);
    assert!(app.is_authenticated(&dpop).await);
}

#[tokio::test]
async fn without_dpop_sessions_the_authorization_and_dpop_headers_are_left_to_the_host() {
    let app = TestApp::with(|r| harness_core(r).session(SessionConfig::default()), |b| b);
    let browser = app.session_as(Client::Browser, "alice@example.com").await;

    let mut authenticator = ResidentAuthenticator::new(&rp_origin());
    let dpop_signup = app
        .finish_signup(Client::Dpop, "bob@example.com", &mut authenticator)
        .await;
    let me = app
        .get("/me")
        .cookie(&browser.token)
        .header("authorization", "DPoP the-hosts-own-token")
        .header("dpop", "the-hosts-own-proof")
        .send()
        .await;

    assert_eq!(dpop_signup.status, StatusCode::FORBIDDEN);
    assert_eq!(dpop_signup.error_code(), "dpop_session_not_allowed");
    assert_eq!(me.status, StatusCode::OK);
}

#[tokio::test]
async fn ending_a_dpop_session_sets_no_cookie() {
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
    let dpop = app.session_as(Client::Dpop, "alice@example.com").await;

    let listed: Vec<SessionDto> = app.get("/auth/sessions").session(&dpop).send().await.json();

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
        transport_of(dpop.session.id),
        Some(SessionTransport::Dpop {
            jkt: dpop.key().jkt()
        })
    );
}
