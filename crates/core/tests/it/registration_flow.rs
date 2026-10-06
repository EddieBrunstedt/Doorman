use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::error::Error;
use doorman_core::session::SessionContext;
use doorman_core::storage::{PasskeyChallengeId, User, UserStore};
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::common::{
    Harness, RECOVERY_URL, SIGNUP_URL, authenticator, kinds, passkey_count, provision_user,
    session_count, session_for, token_from_email,
};

#[derive(Debug, Clone, Copy)]
enum Started {
    Signup,
    Recovery,
    AddPasskey,
}

#[derive(Debug, Clone, Copy)]
enum Finish {
    Signup,
    Recovery,
    AddPasskey,
}

async fn start(
    h: &Harness,
    started: Started,
) -> (User, PasskeyChallengeId, CreationChallengeResponse) {
    match started {
        Started::Signup => {
            h.signup
                .request_signup("new@example.com", None, SessionContext::default())
                .await
                .expect("signup request");
            let email = h.email.sent().pop().expect("signup link queued");
            let token = token_from_email(&email.body_text, SIGNUP_URL);
            let started = h
                .signup
                .redeem_signup_link(&token, SessionContext::default())
                .await
                .expect("signup redeem");
            let user = h
                .users
                .find_user_by_email("new@example.com")
                .await
                .expect("find user")
                .expect("signup provisioned the user");
            (user, started.challenge_id, started.options)
        }
        Started::Recovery => {
            let user = provision_user(h, "alice@example.com").await;
            h.recovery
                .request_recovery("alice@example.com", SessionContext::default())
                .await
                .expect("recovery request");
            let email = h
                .email
                .sent()
                .into_iter()
                .rev()
                .find(|e| e.subject == "Recover access with a new passkey")
                .expect("recovery link queued");
            let token = token_from_email(&email.body_text, RECOVERY_URL);
            let started = h
                .recovery
                .redeem_recovery_link(&token, SessionContext::default())
                .await
                .expect("recovery redeem");
            (user, started.challenge_id, started.options)
        }
        Started::AddPasskey => {
            let user = provision_user(h, "alice@example.com").await;
            let (challenge_id, options) = h
                .passkey
                .start_registration(&session_for(h, &user))
                .await
                .expect("start_registration");
            (user, challenge_id, options)
        }
    }
}

async fn finish(
    h: &Harness,
    finish: Finish,
    challenge_id: PasskeyChallengeId,
    response: &RegisterPublicKeyCredential,
) -> Error {
    let context = SessionContext::default;
    match finish {
        Finish::Signup => h
            .signup
            .finish_signup(challenge_id, response, None, context())
            .await
            .map(drop),
        Finish::Recovery => h
            .recovery
            .finish_recovery(challenge_id, response, None, context())
            .await
            .map(drop),
        Finish::AddPasskey => h
            .passkey
            .finish_registration(challenge_id, response, None, context())
            .await
            .map(drop),
    }
    .expect_err("a registration challenge started for another purpose is refused")
}

async fn assert_refused_as_wrong_purpose(started: Started, finished_as: Finish) {
    let h = Harness::fresh();
    let (user, challenge_id, options) = start(&h, started).await;
    let passkeys_before = passkey_count(&h, user.id).await;
    let sessions_before = session_count(&h, user.id).await;
    let emails_before = h.email.sent().len();
    let audited_before = h.audit.events().len();

    let response = authenticator().do_registration(options);
    let err = finish(&h, finished_as, challenge_id, &response).await;

    assert!(
        matches!(err, Error::InvalidPasskeyChallenge),
        "{started:?} finished as {finished_as:?}: got {err:?}",
    );
    assert_eq!(
        passkey_count(&h, user.id).await,
        passkeys_before,
        "{started:?} finished as {finished_as:?}: no passkey stored",
    );
    assert_eq!(
        session_count(&h, user.id).await,
        sessions_before,
        "{started:?} finished as {finished_as:?}: no session issued",
    );
    assert_eq!(
        h.email.sent().len(),
        emails_before,
        "{started:?} finished as {finished_as:?}: no email sent",
    );
    assert_eq!(
        kinds(&h.audit.events()[audited_before..]),
        vec![AuditEventKind::RedemptionFailed {
            user_id: Some(user.id),
            secret: SecretKind::RegistrationChallenge,
            reason: RedemptionFailureReason::WrongPurpose,
        }],
        "{started:?} finished as {finished_as:?}",
    );
}

#[tokio::test]
async fn signup_challenge_cannot_finish_as_recovery() {
    assert_refused_as_wrong_purpose(Started::Signup, Finish::Recovery).await;
}

#[tokio::test]
async fn signup_challenge_cannot_finish_as_added_passkey() {
    assert_refused_as_wrong_purpose(Started::Signup, Finish::AddPasskey).await;
}

#[tokio::test]
async fn recovery_challenge_cannot_finish_as_signup() {
    assert_refused_as_wrong_purpose(Started::Recovery, Finish::Signup).await;
}

#[tokio::test]
async fn recovery_challenge_cannot_finish_as_added_passkey() {
    assert_refused_as_wrong_purpose(Started::Recovery, Finish::AddPasskey).await;
}

#[tokio::test]
async fn added_passkey_challenge_cannot_finish_as_signup() {
    assert_refused_as_wrong_purpose(Started::AddPasskey, Finish::Signup).await;
}

#[tokio::test]
async fn added_passkey_challenge_cannot_finish_as_recovery() {
    assert_refused_as_wrong_purpose(Started::AddPasskey, Finish::Recovery).await;
}

#[tokio::test]
async fn wrong_purpose_finish_burns_the_challenge() {
    let h = Harness::fresh();
    let (_, challenge_id, options) = start(&h, Started::AddPasskey).await;
    let response = authenticator().do_registration(options);
    finish(&h, Finish::Signup, challenge_id, &response).await;

    let err = finish(&h, Finish::AddPasskey, challenge_id, &response).await;
    assert!(matches!(err, Error::InvalidPasskeyChallenge), "got {err:?}");
}
