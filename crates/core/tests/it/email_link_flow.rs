use chrono::Duration as ChronoDuration;
use doorman_core::audit::{AuditEventKind, RedemptionFailureReason, SecretKind};
use doorman_core::destructive::DestructiveAction;
use doorman_core::error::Error;
use doorman_core::session::SessionContext;
use doorman_core::storage::{UserId, UserStore};

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

    async fn issue(self, h: &Harness) -> (UserId, String) {
        let owner = match self {
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
                    .id
            }
            Link::Recovery => {
                let user = provision_user(h, "alice@example.com").await;
                h.recovery
                    .request_recovery("alice@example.com", SessionContext::default())
                    .await
                    .expect("request recovery");
                user.id
            }
            Link::EmailChange => {
                let user = provision_user(h, "alice@example.com").await;
                h.session_manager
                    .perform(
                        &session_for(h, &user).await,
                        DestructiveAction::RequestEmailChange {
                            new_email: "new@example.com".into(),
                        },
                        None,
                        SessionContext::default(),
                    )
                    .await
                    .expect("request email change");
                user.id
            }
        };
        let prefix = self.template().split('{').next().expect("template prefix");
        let email = h
            .email
            .sent()
            .into_iter()
            .rev()
            .find(|e| e.body_text.contains(prefix))
            .expect("link sent");
        (owner, token_from_email(&email.body_text, self.template()))
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
