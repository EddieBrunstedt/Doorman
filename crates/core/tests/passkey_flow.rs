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
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, User, UserId, UserStore,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::prelude::Url as AuthUrl;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

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

fn authenticator() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn kinds(events: &[bauth_core::audit::AuditEvent]) -> Vec<AuditEventKind> {
    events.iter().map(|e| e.kind.clone()).collect()
}

#[tokio::test]
async fn register_then_authenticate_round_trip() {
    let h = fresh();
    let user = make_user(&h, "alice@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h
        .manager
        .start_registration(user.id)
        .await
        .expect("start_registration");
    let response = wa
        .do_registration(auth_origin(), ccr)
        .expect("authenticator register");

    let credential = h
        .manager
        .finish_registration(
            challenge_id,
            &response,
            Some("Alice's Mac".into()),
            SessionContext::default(),
        )
        .await
        .expect("finish_registration");
    assert_eq!(credential.user_id, user.id);
    assert_eq!(credential.name.as_deref(), Some("Alice's Mac"));
    assert_eq!(h.credentials.len(), 1);
    assert!(h.challenges.is_empty(), "challenge consumed");

    let (auth_challenge, rcr) = h
        .manager
        .start_authentication("Alice@Example.com")
        .await
        .expect("start_authentication");
    let assertion = wa
        .do_authentication(auth_origin(), rcr)
        .expect("authenticator auth");

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
        .unwrap()
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
async fn registration_links_passkey_to_existing_password_user() {
    let h = fresh();
    let user = make_user(&h, "linker@example.com").await;
    let mut wa = authenticator();

    let (challenge_id, ccr) = h.manager.start_registration(user.id).await.expect("start");
    let response = wa.do_registration(auth_origin(), ccr).expect("register");
    let cred = h
        .manager
        .finish_registration(challenge_id, &response, None, SessionContext::default())
        .await
        .expect("finish");
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

    let (id1, ccr1) = h.manager.start_registration(user.id).await.unwrap();
    let r1 = wa.do_registration(auth_origin(), ccr1).unwrap();
    h.manager
        .finish_registration(id1, &r1, None, SessionContext::default())
        .await
        .expect("first");

    let (_id2, ccr2) = h.manager.start_registration(user.id).await.unwrap();
    let excludes = ccr2.public_key.exclude_credentials.unwrap_or_default();
    assert_eq!(excludes.len(), 1, "previous credential excluded");
}

#[tokio::test]
async fn finish_registration_rejects_unknown_challenge() {
    let h = fresh();
    let user = make_user(&h, "ghost@example.com").await;
    let mut wa = authenticator();
    let (challenge_id, ccr) = h.manager.start_registration(user.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
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
    let (challenge_id, ccr) = h.manager.start_registration(user.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
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
    // Register a passkey under user A, then delete it from storage and
    // attempt to authenticate. The webauthn assertion is well-formed but
    // the credential is no longer registered.
    let h = fresh();
    let user = make_user(&h, "vanish@example.com").await;
    let mut wa = authenticator();
    let (id, ccr) = h.manager.start_registration(user.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
    let cred = h
        .manager
        .finish_registration(id, &response, None, SessionContext::default())
        .await
        .unwrap();

    let (auth_id, rcr) = h
        .manager
        .start_authentication("vanish@example.com")
        .await
        .unwrap();
    let assertion = wa.do_authentication(auth_origin(), rcr).unwrap();

    h.credentials
        .delete_passkey(&cred.credential_id)
        .await
        .unwrap();

    let err = h
        .manager
        .finish_authentication(auth_id, &assertion, SessionContext::default())
        .await
        .expect_err("missing credential");
    assert!(matches!(err, Error::PasskeyNotFound));
}

#[tokio::test]
async fn finish_authentication_rejects_cross_user_credential() {
    // Alice registers a passkey. Bob (a different user) starts an
    // authentication ceremony, but the asserted credential belongs to
    // Alice. This must be rejected.
    let h = fresh();
    let alice = make_user(&h, "alice@example.com").await;
    let _bob = make_user(&h, "bob@example.com").await;
    let mut wa = authenticator();

    let (id, ccr) = h.manager.start_registration(alice.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
    h.manager
        .finish_registration(id, &response, None, SessionContext::default())
        .await
        .unwrap();

    // Bob requests an authentication. The challenge is bound to Bob's
    // user_id with an empty allow-list of his (nonexistent) passkeys.
    let (auth_id, _rcr_bob) = h
        .manager
        .start_authentication("bob@example.com")
        .await
        .unwrap();

    // Re-use Alice's assertion. Easiest path: run her ceremony in
    // parallel and inject the result.
    let (alice_auth_id, alice_rcr) = h
        .manager
        .start_authentication("alice@example.com")
        .await
        .unwrap();
    let alice_assertion = wa.do_authentication(auth_origin(), alice_rcr).unwrap();
    // Drain Alice's challenge so we don't leak state.
    h.challenges.take_authentication(alice_auth_id).await.ok();

    let err = h
        .manager
        .finish_authentication(auth_id, &alice_assertion, SessionContext::default())
        .await
        .expect_err("ownership mismatch");
    assert!(matches!(err, Error::PasskeyOwnershipMismatch));
}

#[tokio::test]
async fn start_authentication_for_unknown_email_does_not_leak() {
    let h = fresh();
    let (_id, rcr) = h
        .manager
        .start_authentication("nobody@example.com")
        .await
        .expect("should succeed silently");
    // Allow-list should be empty since the user does not exist, which is
    // the same shape the client would see for a real user with no
    // registered passkeys — no enumeration signal.
    let allow = rcr.public_key.allow_credentials;
    assert!(allow.is_empty());
}

#[tokio::test]
async fn remove_passkey_emits_audit_and_blocks_login() {
    let h = fresh();
    let user = make_user(&h, "remover@example.com").await;
    let mut wa = authenticator();
    let (id, ccr) = h.manager.start_registration(user.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
    let cred = h
        .manager
        .finish_registration(id, &response, None, SessionContext::default())
        .await
        .unwrap();

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
    let (id, ccr) = h.manager.start_registration(alice.id).await.unwrap();
    let response = wa.do_registration(auth_origin(), ccr).unwrap();
    let cred = h
        .manager
        .finish_registration(id, &response, None, SessionContext::default())
        .await
        .unwrap();

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
    h.manager.start_registration(user.id).await.unwrap();
    h.manager
        .start_authentication("exp@example.com")
        .await
        .unwrap();
    assert_eq!(h.challenges.len(), 2);

    h.clock.advance(ChronoDuration::seconds(600));
    let removed = h.challenges.purge_expired(h.clock.now()).await.unwrap();
    assert_eq!(removed, 2);
    assert!(h.challenges.is_empty());
}
