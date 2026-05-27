use std::sync::Arc;
use std::time::Duration;

use bauth_core::audit::{AuditEventKind, AuditSink, AuthMethod, CredentialKind};
use bauth_core::clock::{Clock, MockClock};
use bauth_core::error::Error;
use bauth_core::memory::{
    InMemoryAuditSink, InMemoryPasskeyChallengeStore, InMemoryPasskeyCredentialStore,
    InMemorySessionStore, InMemoryUserStore,
};
use bauth_core::passkey::{PasskeyConfig, PasskeyManager};
use bauth_core::session::{SessionConfig, SessionContext, SessionManager};
use bauth_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, StoredPasskey, User, UserId,
    UserStore,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};
use webauthn_rs_proto::{AllowCredentials, ResidentKeyRequirement};

const RP_ID: &str = "localhost";
const RP_NAME: &str = "bauth tests";

fn rp_origin() -> Url {
    Url::parse("http://localhost:8080").expect("valid url")
}

fn auth_origin() -> AuthUrl {
    AuthUrl::parse("http://localhost:8080").expect("valid auth url")
}

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

struct Harness {
    manager: PasskeyManager,
    users: Arc<InMemoryUserStore>,
    credentials: Arc<InMemoryPasskeyCredentialStore>,
    challenges: Arc<InMemoryPasskeyChallengeStore>,
    sessions: Arc<InMemorySessionStore>,
    audit: Arc<InMemoryAuditSink>,
    clock: Arc<MockClock>,
}

fn fresh() -> Harness {
    let users: Arc<InMemoryUserStore> = Arc::new(InMemoryUserStore::new());
    let credentials: Arc<InMemoryPasskeyCredentialStore> =
        Arc::new(InMemoryPasskeyCredentialStore::new());
    let challenges: Arc<InMemoryPasskeyChallengeStore> =
        Arc::new(InMemoryPasskeyChallengeStore::new());
    let sessions: Arc<InMemorySessionStore> = Arc::new(InMemorySessionStore::new());
    let audit: Arc<InMemoryAuditSink> = Arc::new(InMemoryAuditSink::new());
    let clock: Arc<MockClock> = Arc::new(MockClock::new(ts(2026, 1, 1)));
    let session_manager = SessionManager::new(
        sessions.clone() as Arc<dyn SessionStore>,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        SessionConfig {
            lifetime: Duration::from_secs(60 * 60),
        },
    );
    let manager = PasskeyManager::new(
        users.clone() as Arc<dyn UserStore>,
        credentials.clone() as Arc<dyn PasskeyCredentialStore>,
        challenges.clone() as Arc<dyn PasskeyChallengeStore>,
        session_manager,
        clock.clone() as Arc<dyn Clock>,
        audit.clone() as Arc<dyn AuditSink>,
        PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME),
    )
    .expect("build manager");
    Harness {
        manager,
        users,
        credentials,
        challenges,
        sessions,
        audit,
        clock,
    }
}

async fn make_user(h: &Harness, email: &str) -> User {
    let now = h.clock.now();
    let user = User {
        id: UserId::new(),
        email: Some(email.to_ascii_lowercase()),
        email_verified_at: Some(now),
        created_at: now,
        updated_at: now,
    };
    h.users.create_user(user.clone()).await.expect("create");
    user
}

#[derive(Clone)]
struct ResidentCredential {
    credential_id: Vec<u8>,
    user_handle: Vec<u8>,
}

struct ResidentTestAuthenticator {
    inner: WebauthnAuthenticator<SoftPasskey>,
    resident_credentials: Vec<ResidentCredential>,
}

impl ResidentTestAuthenticator {
    fn new() -> Self {
        Self {
            inner: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            resident_credentials: Vec::new(),
        }
    }

    fn do_registration(
        &mut self,
        challenge: CreationChallengeResponse,
    ) -> RegisterPublicKeyCredential {
        assert_resident_registration_options(&challenge);

        // webauthn-authenticator-rs' SoftPasskey cannot create resident keys yet.
        // The test harness verifies bauth's server options, then relaxes only the
        // local test authenticator input and records the user handle as if the
        // credential had been stored as discoverable.
        let user_handle = challenge.public_key.user.id.as_ref().to_vec();
        let mut compatible_challenge = challenge;
        let selection = compatible_challenge
            .public_key
            .authenticator_selection
            .as_mut()
            .expect("passkey registration includes authenticator selection");
        selection.require_resident_key = false;
        selection.resident_key = None;

        let response = self
            .inner
            .do_registration(auth_origin(), compatible_challenge)
            .expect("authenticator register");
        self.resident_credentials.push(ResidentCredential {
            credential_id: response.raw_id.as_ref().to_vec(),
            user_handle,
        });
        response
    }

    fn do_authentication(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        self.do_authentication_inner(challenge, credential_id, true)
    }

    fn do_authentication_without_user_handle(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
    ) -> PublicKeyCredential {
        self.do_authentication_inner(challenge, credential_id, false)
    }

    fn do_authentication_inner(
        &mut self,
        challenge: RequestChallengeResponse,
        credential_id: &[u8],
        include_user_handle: bool,
    ) -> PublicKeyCredential {
        assert_discoverable_request_options(&challenge);
        let resident = self
            .resident_credentials
            .iter()
            .find(|c| c.credential_id == credential_id)
            .cloned()
            .expect("credential is resident on test authenticator");

        // SoftPasskey still needs an allow-list to pick a key. This is strictly
        // a test-authenticator compatibility shim: the server-issued challenge
        // remains discoverable and contains no allowCredentials.
        let mut compatible_challenge = challenge;
        compatible_challenge.public_key.allow_credentials = vec![AllowCredentials {
            type_: "public-key".to_string(),
            id: resident.credential_id.clone().into(),
            transports: None,
        }];
        let mut assertion = self
            .inner
            .do_authentication(auth_origin(), compatible_challenge)
            .expect("authenticator auth");
        assertion.response.user_handle = include_user_handle.then(|| resident.user_handle.into());
        assertion
    }
}

fn authenticator() -> ResidentTestAuthenticator {
    ResidentTestAuthenticator::new()
}

fn assert_resident_registration_options(challenge: &CreationChallengeResponse) {
    let selection = challenge
        .public_key
        .authenticator_selection
        .as_ref()
        .expect("registration includes authenticator selection");
    assert!(
        selection.require_resident_key,
        "registration must require resident keys"
    );
    assert_eq!(
        selection.resident_key,
        Some(ResidentKeyRequirement::Required),
        "registration must set residentKey=required"
    );
}

fn assert_discoverable_request_options(challenge: &RequestChallengeResponse) {
    assert!(
        challenge.public_key.allow_credentials.is_empty(),
        "discoverable auth must not send allowCredentials"
    );
}

async fn register_passkey(
    h: &Harness,
    user: UserId,
    wa: &mut ResidentTestAuthenticator,
    name: Option<&str>,
) -> StoredPasskey {
    let (challenge_id, ccr) = h
        .manager
        .start_registration(user)
        .await
        .expect("start_registration");
    let response = wa.do_registration(ccr);
    h.manager
        .finish_registration(
            challenge_id,
            &response,
            name.map(ToOwned::to_owned),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration")
}

fn kinds(events: &[bauth_core::audit::AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

#[tokio::test]
async fn register_then_discoverable_authenticate_round_trip() {
    let h = fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();

    let credential = register_passkey(&h, user.id, &mut wa, Some("Alice's Mac")).await;
    assert_eq!(credential.user_id, user.id);
    assert_eq!(credential.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(h.credentials.len(), 1);
    assert!(h.challenges.is_empty(), "challenge consumed");

    let (auth_challenge, rcr) = h
        .manager
        .start_authentication()
        .await
        .expect("start_authentication");
    assert_discoverable_request_options(&rcr);
    let assertion = wa.do_authentication(rcr, &credential.credential_id);

    let issued = h
        .manager
        .finish_authentication(
            auth_challenge,
            &assertion,
            SessionContext {
                ip: Some("1.2.3.4".into()),
                user_agent: Some("ua".into()),
            },
        )
        .await
        .expect("finish_authentication");
    assert_eq!(issued.session.user_id, user.id);
    assert_eq!(h.sessions.len(), 1);

    let stored = h
        .credentials
        .find_passkey_by_credential_id(&credential.credential_id)
        .await
        .expect("find credential")
        .expect("credential persisted");
    assert!(stored.last_used_at.is_some(), "last_used_at advanced");

    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::CredentialAdded {
            credential_kind: CredentialKind::Passkey,
            ..
        }
    )));
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::LoginSucceeded {
            method: AuthMethod::Passkey,
            ..
        }
    )));
}

#[tokio::test]
async fn discoverable_authentication_identifies_two_users_from_response() {
    let h = fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();

    let alice_credential = register_passkey(&h, alice.id, &mut wa, Some("alice device")).await;
    let bob_credential = register_passkey(&h, bob.id, &mut wa, Some("bob device")).await;

    let (bob_challenge, bob_options) = h.manager.start_authentication().await.expect("start bob");
    let bob_assertion = wa.do_authentication(bob_options, &bob_credential.credential_id);
    let bob_issued = h
        .manager
        .finish_authentication(bob_challenge, &bob_assertion, SessionContext::default())
        .await
        .expect("finish bob");
    assert_eq!(bob_issued.session.user_id, bob.id);

    let (alice_challenge, alice_options) =
        h.manager.start_authentication().await.expect("start alice");
    let alice_assertion = wa.do_authentication(alice_options, &alice_credential.credential_id);
    let alice_issued = h
        .manager
        .finish_authentication(alice_challenge, &alice_assertion, SessionContext::default())
        .await
        .expect("finish alice");
    assert_eq!(alice_issued.session.user_id, alice.id);
}

#[tokio::test]
async fn authentication_without_user_handle_falls_back_to_credential_id() {
    let h = fresh();
    let user = make_user(&h, "fallback@example.com").await;
    let mut wa = authenticator();
    let credential = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, options) = h.manager.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication_without_user_handle(options, &credential.credential_id);

    let issued = h
        .manager
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect("finish via credential id fallback");
    assert_eq!(issued.session.user_id, user.id);
}

#[tokio::test]
async fn registration_links_passkey_to_existing_user() {
    let h = fresh();
    let user = make_user(&h, "linker@example.com").await;
    let mut wa = authenticator();

    let cred = register_passkey(&h, user.id, &mut wa, None).await;
    assert_eq!(cred.user_id, user.id, "passkey linked to same user");

    let listed = h.manager.list_passkeys(user.id).await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, cred.credential_id);
}

#[tokio::test]
async fn second_registration_excludes_existing_credentials() {
    let h = fresh();
    let user = make_user(&h, "two@example.com").await;
    let mut wa = authenticator();

    register_passkey(&h, user.id, &mut wa, None).await;

    let (_id2, ccr2) = h
        .manager
        .start_registration(user.id)
        .await
        .expect("start second registration");
    assert_resident_registration_options(&ccr2);
    let excludes = ccr2
        .public_key
        .exclude_credentials
        .expect("previous credential excluded");
    assert_eq!(excludes.len(), 1, "previous credential excluded");
}

#[tokio::test]
async fn finish_registration_rejects_unknown_challenge() {
    let h = fresh();
    let user = make_user(&h, "ghost@example.com").await;
    let mut wa = authenticator();
    let (challenge_id, ccr) = h.manager.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(ccr);
    h.manager
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("first finish ok");

    let err = h
        .manager
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("replayed challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_registration_rejects_expired_challenge() {
    let h = fresh();
    let user = make_user(&h, "slow@example.com").await;
    let mut wa = authenticator();
    let (challenge_id, ccr) = h.manager.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(ccr);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .manager
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect_err("expired");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn finish_authentication_rejects_unknown_credential() {
    let h = fresh();
    let user = make_user(&h, "vanish@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.manager.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);

    h.credentials
        .delete_passkey(&cred.credential_id)
        .await
        .expect("delete credential");

    let err = h
        .manager
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn finish_authentication_rejects_mismatched_user_handle() {
    let h = fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();
    let alice_credential = register_passkey(&h, alice.id, &mut wa, None).await;

    let (auth_id, rcr) = h.manager.start_authentication().await.expect("start auth");
    let mut assertion = wa.do_authentication(rcr, &alice_credential.credential_id);
    assertion.response.user_handle = Some(bob.id.0.as_bytes().as_slice().into());

    let err = h
        .manager
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("ownership mismatch");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
}

#[tokio::test]
async fn start_authentication_is_usernameless_and_does_not_look_up_email() {
    let h = fresh();
    let (_id, rcr) = h
        .manager
        .start_authentication()
        .await
        .expect("should succeed without an email");
    assert_discoverable_request_options(&rcr);
}

#[tokio::test]
async fn finish_authentication_rejects_expired_challenge() {
    let h = fresh();
    let user = make_user(&h, "slow-auth@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    let (auth_id, rcr) = h.manager.start_authentication().await.expect("start auth");
    let assertion = wa.do_authentication(rcr, &cred.credential_id);
    h.clock.advance(ChronoDuration::seconds(301));

    let err = h
        .manager
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("expired challenge");
    assert!(matches!(err, Error::InvalidPasskeyChallenge));
}

#[tokio::test]
async fn remove_passkey_emits_audit_and_blocks_login() {
    let h = fresh();
    let user = make_user(&h, "remover@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, user.id, &mut wa, None).await;

    h.manager
        .remove_passkey(user.id, &cred.credential_id, SessionContext::default())
        .await
        .expect("remove");
    assert!(h.credentials.is_empty());
    let events = kinds(&h.audit.events());
    assert!(events.iter().any(|k| matches!(
        k,
        AuditEventKind::CredentialRemoved {
            credential_kind: CredentialKind::Passkey,
            ..
        }
    )));
}

#[tokio::test]
async fn remove_passkey_refuses_other_users_credential() {
    let h = fresh();
    let alice = make_user(&h, "a@example.com").await;
    let bob = make_user(&h, "b@example.com").await;
    let mut wa = authenticator();
    let cred = register_passkey(&h, alice.id, &mut wa, None).await;

    let err = h
        .manager
        .remove_passkey(bob.id, &cred.credential_id, SessionContext::default())
        .await
        .expect_err("ownership check");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
    assert_eq!(h.credentials.len(), 1, "alice's passkey untouched");
}

#[tokio::test]
async fn start_registration_for_unknown_user_errors() {
    let h = fresh();
    let err = h
        .manager
        .start_registration(UserId::new())
        .await
        .expect_err("unknown user");
    assert!(matches!(err, Error::UserNotFound));
}

#[tokio::test]
async fn challenge_store_purges_expired_entries() {
    let h = fresh();
    let user = make_user(&h, "exp@example.com").await;
    h.manager
        .start_registration(user.id)
        .await
        .expect("start registration");
    h.manager
        .start_authentication()
        .await
        .expect("start authentication");
    assert_eq!(h.challenges.len(), 2);

    h.clock.advance(ChronoDuration::seconds(600));
    let removed = h
        .challenges
        .purge_expired(h.clock.now())
        .await
        .expect("purge expired");
    assert_eq!(removed, 2);
    assert!(h.challenges.is_empty());
}
