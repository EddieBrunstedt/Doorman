use chrono::Duration as ChronoDuration;
use doorman_core::audit::{
    AuditEventKind, RecoveryFailureReason, RedemptionFailureReason, SecretKind, SignupFailureReason,
};
use doorman_core::clock::Clock;
use doorman_core::destructive::DestructiveAction;
use doorman_core::error::Error;
use doorman_core::session::SessionContext;
use doorman_core::storage::{User, UserId, UserStatus, UserStore};

use crate::common::{
    Harness, RECOVERY_URL, SIGNUP_URL, USER_URL, kinds, provision_user, session_for,
    token_from_email,
};

#[derive(Debug, Clone, Copy, PartialEq)]
enum Link {
    Signup,
    Recovery,
    EmailChange,
}

const LINKS: [Link; 3] = [Link::Signup, Link::Recovery, Link::EmailChange];

impl Link {
    fn secret(self) -> SecretKind {
        match self {
            Link::Signup => SecretKind::SignupLink,
            Link::Recovery => SecretKind::RecoveryLink,
            Link::EmailChange => SecretKind::EmailChangeLink,
        }
    }

    fn template(self) -> &'static str {
        match self {
            Link::Signup => SIGNUP_URL,
            Link::Recovery => RECOVERY_URL,
            Link::EmailChange => USER_URL,
        }
    }

    // Signup creates the user it sends a link to, so its owner already holds one.
    async fn owner(self, h: &Harness) -> User {
        match self {
            Link::Signup => {
                h.signup
                    .request_signup("new@example.com", None, SessionContext::default())
                    .await
                    .expect("request signup");
                h.users
                    .find_user_by_email("new@example.com")
                    .await
                    .expect("find user")
                    .expect("signup provisioned the user")
            }
            Link::Recovery | Link::EmailChange => provision_user(h, "alice@example.com").await,
        }
    }

    async fn request(self, h: &Harness, owner: &User) -> Result<(), Error> {
        let context = SessionContext::default();
        match self {
            Link::Signup => {
                h.signup
                    .request_signup("new@example.com", None, context)
                    .await
            }
            Link::Recovery => {
                h.recovery
                    .request_recovery("alice@example.com", context)
                    .await
            }
            Link::EmailChange => h
                .session_manager
                .perform(
                    &session_for(h, owner).await,
                    DestructiveAction::RequestEmailChange {
                        new_email: "new@example.com".into(),
                    },
                    None,
                    context,
                )
                .await
                .map(drop),
        }
    }

    async fn issue(self, h: &Harness) -> (UserId, String) {
        let owner = self.owner(h).await;
        self.request(h, &owner).await.expect("request link");
        let prefix = self.template().split('{').next().expect("template prefix");
        let email = h
            .email
            .sent()
            .into_iter()
            .rev()
            .find(|e| e.body_text.contains(prefix))
            .expect("link sent");
        (
            owner.id,
            token_from_email(&email.body_text, self.template()),
        )
    }

    async fn redeem(self, h: &Harness, token: &str) -> Result<(), Error> {
        let context = SessionContext::default();
        match self {
            Link::Signup => h.signup.redeem_signup_link(token, context).await.map(drop),
            Link::Recovery => h
                .recovery
                .redeem_recovery_link(token, context)
                .await
                .map(drop),
            Link::EmailChange => h.user.confirm_email_change(token, context).await.map(drop),
        }
    }
}

fn refused_issue(link: Link, owner: UserId) -> Option<AuditEventKind> {
    match link {
        Link::Signup => Some(AuditEventKind::SignupFailed {
            user_id: owner,
            reason: SignupFailureReason::UserDisabled,
        }),
        Link::Recovery => Some(AuditEventKind::RecoveryFailed {
            user_id: Some(owner),
            reason: RecoveryFailureReason::UserDisabled,
        }),
        Link::EmailChange => None,
    }
}

// Through the store, so only the status changes: the owner keeps their sessions and links.
async fn disable(h: &Harness, owner: UserId) {
    let now = h.clock.now();
    h.users
        .set_user_status(owner, UserStatus::Disabled { at: now }, now)
        .await
        .expect("disable owner");
}

fn audited_failure(
    h: &Harness,
    link: Link,
    owner: Option<UserId>,
    reason: RedemptionFailureReason,
) -> bool {
    kinds(&h.audit.events()).iter().any(|k| {
        *k == AuditEventKind::RedemptionFailed {
            user_id: owner,
            secret: link.secret(),
            reason,
        }
    })
}

#[tokio::test]
async fn a_link_presented_for_another_purpose_is_refused_and_redeemed() {
    for issued in LINKS {
        for other in LINKS.into_iter().filter(|l| *l != issued) {
            let h = Harness::fresh();
            let (owner, token) = issued.issue(&h).await;

            let err = other.redeem(&h, &token).await.expect_err("wrong purpose");
            assert!(
                matches!(err, Error::InvalidEmailLink),
                "{issued:?} link at {other:?}"
            );
            assert!(
                audited_failure(
                    &h,
                    other,
                    Some(owner),
                    RedemptionFailureReason::WrongPurpose
                ),
                "{issued:?} link at {other:?}"
            );

            let err = issued
                .redeem(&h, &token)
                .await
                .expect_err("the link was redeemed");
            assert!(
                matches!(err, Error::InvalidEmailLink),
                "{issued:?} link after {other:?}"
            );
        }
    }
}

#[tokio::test]
async fn a_redeemed_link_cannot_be_replayed() {
    for link in LINKS {
        let h = Harness::fresh();
        let (_, token) = link.issue(&h).await;
        link.redeem(&h, &token).await.expect("first redeem");

        let err = link.redeem(&h, &token).await.expect_err("replay");

        assert!(matches!(err, Error::InvalidEmailLink), "{link:?}");
        assert!(
            audited_failure(&h, link, None, RedemptionFailureReason::Unknown),
            "{link:?}"
        );
    }
}

#[tokio::test]
async fn an_expired_link_is_refused_without_an_email() {
    for link in LINKS {
        let h = Harness::fresh();
        let (owner, token) = link.issue(&h).await;
        let mail_before = h.email.sent().len();
        h.clock.advance(ChronoDuration::minutes(16));

        let err = link.redeem(&h, &token).await.expect_err("expired");

        assert!(matches!(err, Error::InvalidEmailLink), "{link:?}");
        assert_eq!(h.email.sent().len(), mail_before, "{link:?}");
        assert!(
            audited_failure(&h, link, Some(owner), RedemptionFailureReason::Expired),
            "{link:?}"
        );
    }
}

#[tokio::test]
async fn a_tampered_link_is_refused_and_the_real_one_still_redeems() {
    for link in LINKS {
        let h = Harness::fresh();
        let (_, token) = link.issue(&h).await;
        let mut tampered: Vec<char> = token.chars().collect();
        tampered[0] = if tampered[0] == 'a' { 'b' } else { 'a' };
        let tampered: String = tampered.into_iter().collect();

        let err = link.redeem(&h, &tampered).await.expect_err("tampered");

        assert!(matches!(err, Error::InvalidEmailLink), "{link:?}");
        assert!(
            audited_failure(&h, link, None, RedemptionFailureReason::Unknown),
            "{link:?}"
        );
        link.redeem(&h, &token)
            .await
            .expect("the real link redeems");
    }
}

#[tokio::test]
async fn a_link_is_refused_once_its_owners_email_address_has_changed() {
    for link in LINKS {
        let h = Harness::fresh();
        let (owner, token) = link.issue(&h).await;
        h.users
            .set_user_email(owner, "moved@example.com", h.clock.now())
            .await
            .expect("change address");

        let err = link.redeem(&h, &token).await.expect_err("address changed");

        assert!(matches!(err, Error::InvalidEmailLink), "{link:?}");
        assert!(
            audited_failure(&h, link, Some(owner), RedemptionFailureReason::EmailChanged),
            "{link:?}"
        );
    }
}

#[tokio::test]
async fn no_link_is_issued_to_a_disabled_user() {
    for link in LINKS {
        let h = Harness::fresh();
        let owner = link.owner(&h).await;
        disable(&h, owner.id).await;
        let mail_before = h.email.sent().len();

        let result = link.request(&h, &owner).await;

        assert_eq!(h.email.sent().len(), mail_before, "{link:?}");
        match refused_issue(link, owner.id) {
            // Signup and recovery answer a disabled user as they answer anyone, so the response
            // reveals nothing about them.
            Some(refusal) => {
                result.expect("silent ok");
                assert!(kinds(&h.audit.events()).contains(&refusal), "{link:?}");
            }
            None => assert!(matches!(result, Err(Error::UserDisabled)), "{link:?}"),
        }
    }
}

#[tokio::test]
async fn a_link_is_refused_while_its_owner_is_disabled() {
    for link in LINKS {
        let h = Harness::fresh();
        let (owner, token) = link.issue(&h).await;
        disable(&h, owner).await;

        let err = link.redeem(&h, &token).await.expect_err("owner disabled");

        assert!(matches!(err, Error::UserDisabled), "{link:?}");
        assert!(
            audited_failure(&h, link, Some(owner), RedemptionFailureReason::UserDisabled),
            "{link:?}"
        );
    }
}
