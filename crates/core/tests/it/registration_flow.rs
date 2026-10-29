use std::num::NonZeroU32;

use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::clock::Clock;
use doorman_core::error::Error;
use doorman_core::passkey::{PasskeyConfig, RegistrationOutcome, StartedRegistration};
use doorman_core::session::ResolvedSession;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeyChallengeStore, SessionTransport, User, UserStatus, UserStore,
};
use doorman_test_support::request_context;
use webauthn_rs::prelude::{CreationChallengeResponse, RegisterPublicKeyCredential};

use crate::common::{
    Harness, LOCK_OUTS, LockOut, RECOVERY_URL, RP_ID, RP_NAME, SIGNUP_URL, authenticator, kinds,
    locked_out_during, operator, passkey_count, provision_user, rp_origin, session_count,
    session_for, token_from_email,
};

#[derive(Debug, Clone, Copy)]
enum Link {
    Signup,
    Recovery,
}

const LINKS: [Link; 2] = [Link::Signup, Link::Recovery];

impl Link {
    fn secret(self) -> SecretKind {
        match self {
            Link::Signup => SecretKind::SignupLink,
            Link::Recovery => SecretKind::RecoveryLink,
        }
    }

    async fn issue(self, h: &Harness) -> (User, String) {
        match self {
            Link::Signup => {
                h.signup
                    .request_signup("new@example.com", None, request_context())
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
                    .request_recovery("alice@example.com", request_context())
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
        let context = request_context();
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
        let context = request_context();
        match self {
            Link::Signup => {
                h.signup
                    .finish_signup(
                        started.challenge_id,
                        &response,
                        name,
                        SessionTransport::Cookie,
                        context,
                    )
                    .await
            }
            Link::Recovery => {
                h.recovery
                    .finish_recovery(
                        started.challenge_id,
                        &response,
                        name,
                        SessionTransport::Cookie,
                        context,
                    )
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
                    transport: SessionTransport::Cookie,
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
                request_context(),
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
                request_context(),
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

#[tokio::test]
async fn an_email_link_registration_from_before_a_disable_cannot_finish_after_an_enable() {
    for link in LINKS {
        let h = Harness::fresh();
        let (user, token) = link.issue(&h).await;
        let started = link.redeem(&h, &token).await.expect("redeem while active");
        h.operator
            .disable(user.id, operator())
            .await
            .expect("disable");
        h.operator
            .enable(user.id, operator())
            .await
            .expect("enable");
        let passkeys_before = passkey_count(&h, user.id).await;

        let err = link
            .finish(&h, started)
            .await
            .expect_err("registration deleted");

        assert!(
            matches!(err, Error::InvalidPasskeyChallenge),
            "{link:?}: {err:?}"
        );
        assert_eq!(
            passkey_count(&h, user.id).await,
            passkeys_before,
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
    let context = request_context;
    match finish {
        Finish::Signup => h
            .signup
            .finish_signup(
                challenge_id,
                response,
                None,
                SessionTransport::Cookie,
                context(),
            )
            .await
            .map(drop),
        Finish::Recovery => h
            .recovery
            .finish_recovery(
                challenge_id,
                response,
                None,
                SessionTransport::Cookie,
                context(),
            )
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

// Ready to make the call that starts a registration.
enum Starter {
    Link(Link, String),
    Session(ResolvedSession),
}

impl Starter {
    async fn ready(h: &Harness, started: Started) -> (User, Starter) {
        let link = match started {
            Started::Signup => Link::Signup,
            Started::Recovery => Link::Recovery,
            Started::AddPasskey => {
                let user = provision_user(h, "alice@example.com").await;
                let session = session_for(h, &user).await;
                return (user, Starter::Session(session));
            }
        };
        let (user, token) = link.issue(h).await;
        (user, Starter::Link(link, token))
    }

    async fn start(&self, h: &Harness) -> Result<(), Error> {
        match self {
            Starter::Link(link, token) => link.redeem(h, token).await.map(drop),
            Starter::Session(session) => h
                .session_manager
                .start_passkey_registration(session)
                .await
                .map(drop),
        }
    }
}

#[tokio::test]
async fn a_registration_started_while_its_owner_is_locked_out_does_not_survive() {
    for started in [Started::Signup, Started::Recovery, Started::AddPasskey] {
        for lock_out in LOCK_OUTS {
            let h = Harness::fresh();
            let (user, starter) = Starter::ready(&h, started).await;
            let audited_before = h.audit.events().len();

            // The lock-out lands once the owner has been checked, while the registration is
            // being written.
            let held = h.challenge_store.hold_next_registration_write();
            let result = locked_out_during(&h, held, lock_out, user.id, starter.start(&h)).await;

            let case = format!("{started:?} racing {lock_out:?}");
            let audited = kinds(&h.audit.events()[audited_before..]);
            match (&starter, lock_out) {
                // A link is refused as if the lock-out had come before it was redeemed.
                (Starter::Link(link, _), _) => {
                    let (refused, reason) = match lock_out {
                        LockOut::Disable => (
                            matches!(result, Err(Error::UserDisabled)),
                            RedemptionFailureReason::UserDisabled,
                        ),
                        LockOut::Delete => (
                            matches!(result, Err(Error::InvalidEmailLink)),
                            RedemptionFailureReason::UserNotFound,
                        ),
                    };
                    assert!(refused, "{case}: got {result:?}");
                    assert!(
                        audited.contains(&AuditEventKind::RedemptionFailed {
                            user_id: Some(user.id),
                            secret: link.secret(),
                            reason,
                        }),
                        "{case}: {audited:?}"
                    );
                    assert!(!audited.contains(&link.redeemed(&user)), "{case}");
                }
                (Starter::Session(_), LockOut::Disable) => assert!(
                    matches!(result, Err(Error::UserDisabled)),
                    "{case}: got {result:?}"
                ),
                (Starter::Session(_), LockOut::Delete) => assert!(
                    matches!(result, Err(Error::UserNotFound)),
                    "{case}: got {result:?}"
                ),
            }
            let left = h
                .challenges
                .list_registrations_for_user(user.id)
                .await
                .expect("list registrations");
            assert!(left.is_empty(), "{case}: the registration is discarded");
        }
    }
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
