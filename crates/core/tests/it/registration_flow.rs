use std::num::NonZeroU32;

use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::error::Error;
use doorman_core::passkey::{
    PasskeyConfig, PasskeyRateLimits, RegistrationOutcome, StartedRegistration,
};
use doorman_core::session::{ResolvedSession, SessionContext};
use doorman_core::storage::{PasskeyChallengeId, User, UserStatus, UserStore};
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::common::{
    Harness, RECOVERY_URL, RP_ID, RP_NAME, SIGNUP_URL, authenticator, kinds, passkey_count,
    provision_user, rp_origin, session_count, session_for, token_from_email,
};

#[derive(Debug, Clone, Copy)]
enum Link {
    Signup,
    Recovery,
}

const LINKS: [Link; 2] = [Link::Signup, Link::Recovery];

impl Link {
    async fn issue(self, h: &Harness) -> (User, String) {
        match self {
            Link::Signup => {
                h.signup
                    .request_signup("new@example.com", None, SessionContext::default())
                    .await
                    .expect("signup request");
                let email = h.email.sent().pop().expect("signup link queued");
                let user = h
                    .users
                    .find_user_by_email("new@example.com")
                    .await
                    .expect("find user")
                    .expect("signup provisioned the user");
                (user, token_from_email(&email.body_text, SIGNUP_URL))
            }
            Link::Recovery => {
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
                (user, token_from_email(&email.body_text, RECOVERY_URL))
            }
        }
    }

    async fn redeem(self, h: &Harness, token: &str) -> Result<StartedRegistration, Error> {
        let context = SessionContext::default();
        match self {
            Link::Signup => h.signup.redeem_signup_link(token, context).await,
            Link::Recovery => h.recovery.redeem_recovery_link(token, context).await,
        }
    }

    async fn finish(
        self,
        h: &Harness,
        started: StartedRegistration,
    ) -> Result<RegistrationOutcome, Error> {
        let response = authenticator().do_registration(started.options);
        let name = Some("new device".to_owned());
        let context = SessionContext::default();
        match self {
            Link::Signup => {
                h.signup
                    .finish_signup(started.challenge_id, &response, name, context)
                    .await
            }
            Link::Recovery => {
                h.recovery
                    .finish_recovery(started.challenge_id, &response, name, context)
                    .await
            }
        }
    }

    fn redeemed(self, user: &User) -> AuditEventKind {
        match self {
            Link::Signup => AuditEventKind::SignupLinkRedeemed { user_id: user.id },
            Link::Recovery => AuditEventKind::RecoveryLinkRedeemed { user_id: user.id },
        }
    }
}

#[tokio::test]
async fn an_email_link_registration_stores_the_passkey_and_starts_a_session() {
    for link in LINKS {
        let h = Harness::fresh();
        let (user, token) = link.issue(&h).await;
        let passkeys_before = passkey_count(&h, user.id).await;
        let sessions_before = session_count(&h, user.id).await;

        let audited_before = h.audit.events().len();
        let started = link.redeem(&h, &token).await.expect("redeem");
        assert_eq!(
            kinds(&h.audit.events()[audited_before..]),
            vec![link.redeemed(&user)],
            "{link:?}",
        );

        let audited_before = h.audit.events().len();
        let outcome = link.finish(&h, started).await.expect("finish");

        assert_eq!(outcome.user.id, user.id, "{link:?}");
        assert_eq!(outcome.session.session.user_id, user.id, "{link:?}");
        assert_eq!(
            outcome.passkey.name.as_deref(),
            Some("new device"),
            "{link:?}"
        );
        assert_eq!(
            passkey_count(&h, user.id).await,
            passkeys_before + 1,
            "{link:?}"
        );
        assert_eq!(
            session_count(&h, user.id).await,
            sessions_before + 1,
            "{link:?}"
        );
        assert_eq!(
            kinds(&h.audit.events()[audited_before..]),
            vec![
                AuditEventKind::PasskeyAdded { user_id: user.id },
                AuditEventKind::SessionCreated {
                    user_id: user.id,
                    session_id: outcome.session.session.id,
                },
                AuditEventKind::LoginSucceeded { user_id: user.id },
            ],
            "{link:?}",
        );
    }
}

#[tokio::test]
async fn redeeming_an_email_link_replaces_unfinished_registrations_rather_than_hitting_the_pending_cap()
 {
    for link in LINKS {
        let h = Harness::builder()
            .passkey_config(PasskeyConfig {
                rate_limits: PasskeyRateLimits::disabled(),
                max_pending_registrations_per_user: NonZeroU32::new(1),
                ..PasskeyConfig::new(RP_ID, rp_origin(), RP_NAME)
            })
            .build();
        let (user, token) = link.issue(&h).await;
        let session = session_for(&h, &user).await;
        let (stale_id, stale_options) = h
            .session_manager
            .start_passkey_registration(&session)
            .await
            .expect("fill the cap");
        let err = h
            .session_manager
            .start_passkey_registration(&session)
            .await
            .expect_err("the cap is full");
        assert!(
            matches!(err, Error::ResourceLimitExceeded { .. }),
            "{link:?}: {err:?}"
        );

        let started = link
            .redeem(&h, &token)
            .await
            .expect("redeem starts a registration despite the full cap");

        let err = h
            .session_manager
            .finish_passkey_registration(
                &session,
                stale_id,
                &authenticator().do_registration(stale_options),
                None,
                SessionContext::default(),
            )
            .await
            .expect_err("the unfinished registration was replaced");
        assert!(
            matches!(err, Error::InvalidPasskeyChallenge),
            "{link:?}: {err:?}"
        );
        link.finish(&h, started)
            .await
            .expect("the link's registration finishes");
    }
}

#[tokio::test]
async fn finishing_an_email_link_registration_drops_registrations_started_since_the_redeem() {
    for link in LINKS {
        let h = Harness::fresh();
        let (user, token) = link.issue(&h).await;
        let started = link.redeem(&h, &token).await.expect("redeem");
        let session = session_for(&h, &user).await;
        let (meanwhile_id, meanwhile_options) = h
            .session_manager
            .start_passkey_registration(&session)
            .await
            .expect("start a registration after the redeem");

        link.finish(&h, started).await.expect("finish");

        let err = h
            .session_manager
            .finish_passkey_registration(
                &session,
                meanwhile_id,
                &authenticator().do_registration(meanwhile_options),
                None,
                SessionContext::default(),
            )
            .await
            .expect_err("the registration started meanwhile was dropped");
        assert!(
            matches!(err, Error::InvalidPasskeyChallenge),
            "{link:?}: {err:?}"
        );
    }
}

#[tokio::test]
async fn an_email_link_registration_cannot_finish_for_a_disabled_user() {
    for link in LINKS {
        let h = Harness::fresh();
        let (user, token) = link.issue(&h).await;
        let started = link.redeem(&h, &token).await.expect("redeem while active");
        let passkeys_before = passkey_count(&h, user.id).await;
        let sessions_before = session_count(&h, user.id).await;
        let now = h.clock.now();
        h.users
            .set_user_status(user.id, UserStatus::Disabled { at: now }, now)
            .await
            .expect("disable user");

        let err = link
            .finish(&h, started)
            .await
            .expect_err("finish refused for a disabled user");

        assert!(matches!(err, Error::UserDisabled), "{link:?}: {err:?}");
        assert_eq!(
            passkey_count(&h, user.id).await,
            passkeys_before,
            "{link:?}"
        );
        assert_eq!(
            session_count(&h, user.id).await,
            sessions_before,
            "{link:?}"
        );
    }
}

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

// The session is the user's, so a finish as an added passkey has one to present.
async fn start(
    h: &Harness,
    started: Started,
) -> (
    User,
    ResolvedSession,
    PasskeyChallengeId,
    CreationChallengeResponse,
) {
    let link = match started {
        Started::Signup => Link::Signup,
        Started::Recovery => Link::Recovery,
        Started::AddPasskey => {
            let user = provision_user(h, "alice@example.com").await;
            let session = session_for(h, &user).await;
            let (challenge_id, options) = h
                .session_manager
                .start_passkey_registration(&session)
                .await
                .expect("start_registration");
            return (user, session, challenge_id, options);
        }
    };
    let (user, token) = link.issue(h).await;
    let started = link.redeem(h, &token).await.expect("redeem");
    let session = session_for(h, &user).await;
    (user, session, started.challenge_id, started.options)
}

async fn finish(
    h: &Harness,
    finish: Finish,
    session: &ResolvedSession,
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
            .session_manager
            .finish_passkey_registration(session, challenge_id, response, None, context())
            .await
            .map(drop),
    }
    .expect_err("a registration challenge started for another purpose is refused")
}

async fn assert_refused_as_wrong_purpose(started: Started, finished_as: Finish) {
    let h = Harness::fresh();
    let (user, session, challenge_id, options) = start(&h, started).await;
    let passkeys_before = passkey_count(&h, user.id).await;
    let sessions_before = session_count(&h, user.id).await;
    let emails_before = h.email.sent().len();
    let audited_before = h.audit.events().len();

    let response = authenticator().do_registration(options);
    let err = finish(&h, finished_as, &session, challenge_id, &response).await;

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
    let (_, session, challenge_id, options) = start(&h, Started::AddPasskey).await;
    let response = authenticator().do_registration(options);
    finish(&h, Finish::Signup, &session, challenge_id, &response).await;

    let err = finish(&h, Finish::AddPasskey, &session, challenge_id, &response).await;
    assert!(matches!(err, Error::InvalidPasskeyChallenge), "got {err:?}");
}
