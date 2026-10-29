use std::future::Future;

use doorman_core::error::StorageErrorKind;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, ExpiringStores, PasskeyChallengeId,
    RegistrationPurpose, Session, SessionId, SessionTransport, StoredPasskeyAuthentication,
    StoredPasskeyRegistration, UserId,
};

use crate::fixtures::{RACERS, assert_refused, days, link, present};

async fn count_redeemers<F, Fut>(redeem: F) -> usize
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool> + Send + 'static,
{
    let racers: Vec<_> = (0..RACERS).map(|_| tokio::spawn(redeem())).collect();
    let mut redeemed = 0;
    for racer in racers {
        if racer.await.expect("racer task") {
            redeemed += 1;
        }
    }
    redeemed
}

pub(crate) async fn single_use_under_concurrency(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let hash = hash_token("race-redeem-token");
    stores
        .email_links
        .replace_link(EmailLink {
            token_hash: hash,
            user_id,
            purpose: EmailLinkPurpose::Signup,
            owner_email: None,
            new_email: None,
            created_at: now,
            expires_at: days(365),
        })
        .await
        .expect("create token");
    let redeemed = count_redeemers(|| {
        let tokens = stores.email_links.clone();
        async move { tokens.redeem_link(&hash).await.expect("redeem").is_some() }
    })
    .await;
    assert_eq!(redeemed, 1, "exactly one caller redeems the token");

    let registration = PasskeyChallengeId::new();
    stores
        .passkey_challenges
        .put_registration(StoredPasskeyRegistration {
            id: registration,
            purpose: RegistrationPurpose::AddPasskey,
            user_id,
            state: b"race-registration".to_vec(),
            owner_email: None,
            created_at: now,
            expires_at: days(365),
            recovery_cool_down_until: None,
        })
        .await
        .expect("put registration");
    let taken = count_redeemers(|| {
        let challenges = stores.passkey_challenges.clone();
        async move {
            challenges
                .take_registration(registration)
                .await
                .expect("take registration")
                .is_some()
        }
    })
    .await;
    assert_eq!(taken, 1, "exactly one caller takes the registration");

    let authentication = PasskeyChallengeId::new();
    stores
        .passkey_challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: authentication,
            purpose: AuthenticationPurpose::Login,
            state: b"race-authentication".to_vec(),
            created_at: now,
            expires_at: days(365),
        })
        .await
        .expect("put authentication");
    let taken = count_redeemers(|| {
        let challenges = stores.passkey_challenges.clone();
        async move {
            challenges
                .take_authentication(authentication)
                .await
                .expect("take authentication")
                .is_some()
        }
    })
    .await;
    assert_eq!(taken, 1, "exactly one caller takes the authentication");
}

pub(crate) async fn owner_indexes_track_removals(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;
    let session = |token: &str, expires_at| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        transport: SessionTransport::Cookie,
        created_at: days(-2),
        last_used_at: days(-2),
        expires_at,
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let deleted = session("index-deleted-session", days(365));
    let expired = session("index-expired-session", days(-1));
    let kept = session("index-kept-session", days(365));
    let other = session("index-other-session", days(365));
    for s in [&deleted, &expired, &kept, &other] {
        sessions
            .create_session(s.clone())
            .await
            .expect("create session");
    }
    sessions
        .delete_session(deleted.id)
        .await
        .expect("delete session");
    assert!(
        sessions.purge_expired(now).await.expect("purge sessions") >= 1,
        "the expired session was purged",
    );
    assert_eq!(
        sessions
            .delete_sessions_for_user(user_id, Some(kept.id))
            .await
            .expect("delete other sessions"),
        1,
        "only the one remaining other session is removed",
    );
    assert_eq!(
        sessions
            .delete_sessions_for_user(user_id, None)
            .await
            .expect("delete sessions"),
        1,
        "only the kept session is left to remove",
    );

    let tokens = &stores.email_links;
    let token = |raw: &str, purpose, expires_at| EmailLink {
        created_at: days(-2),
        expires_at,
        ..link(raw, user_id, purpose)
    };
    let replaced = token("index-replaced-token", EmailLinkPurpose::Signup, days(365));
    let redeemed = token("index-redeemed-token", EmailLinkPurpose::Signup, days(365));
    let expired = token("index-expired-token", EmailLinkPurpose::Recovery, days(-1));
    let remaining = token(
        "index-remaining-token",
        EmailLinkPurpose::EmailChange,
        days(365),
    );
    for t in [&replaced, &redeemed, &expired, &remaining] {
        tokens.replace_link(t.clone()).await.expect("create token");
    }
    assert!(
        tokens
            .redeem_link(&redeemed.token_hash)
            .await
            .expect("redeem token")
            .is_some(),
        "the token is redeemed",
    );
    assert!(
        tokens.purge_expired(now).await.expect("purge tokens") >= 1,
        "the expired token was purged",
    );
    assert_eq!(
        tokens
            .delete_links_for_user(user_id)
            .await
            .expect("delete tokens"),
        1,
        "only the remaining token is left to remove",
    );

    let challenges = &stores.passkey_challenges;
    let registration = |expires_at| StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::AddPasskey,
        user_id,
        state: b"index-registration".to_vec(),
        owner_email: None,
        created_at: days(-2),
        expires_at,
        recovery_cool_down_until: None,
    };
    let taken = registration(days(365));
    let expired = registration(days(-1));
    let remaining = registration(days(365));
    for r in [&taken, &expired, &remaining] {
        challenges
            .put_registration(r.clone())
            .await
            .expect("put registration");
    }
    let count = || async {
        challenges
            .list_registrations_for_user(user_id)
            .await
            .expect("count registrations")
            .len()
    };
    assert_eq!(count().await, 3, "all three registrations are listed");
    assert!(
        challenges
            .take_registration(taken.id)
            .await
            .expect("take registration")
            .is_some(),
        "the registration is taken",
    );
    assert_eq!(count().await, 2, "a taken registration is no longer listed");
    assert!(
        challenges
            .purge_expired(now)
            .await
            .expect("purge challenges")
            >= 1,
        "the expired registration was purged",
    );
    assert_eq!(
        count().await,
        1,
        "a purged registration is no longer listed"
    );
    assert_eq!(
        challenges
            .delete_registrations_for_user(user_id)
            .await
            .expect("delete registrations"),
        1,
        "only the remaining registration is left to remove",
    );
    assert_eq!(count().await, 0, "no registrations remain");
}

pub(crate) async fn absent_lookups_return_none(stores: &ExpiringStores) {
    assert!(
        stores
            .sessions
            .find_session_by_id(SessionId::new())
            .await
            .expect("absent session by id")
            .is_none(),
        "an unknown session id resolves to None",
    );
    assert!(
        stores
            .sessions
            .find_session_by_token_hash(&hash_token("no-such-session"))
            .await
            .expect("absent session by hash")
            .is_none(),
        "an unknown session token hash resolves to None",
    );
    assert!(
        stores
            .email_links
            .redeem_link(&hash_token("no-such-token"))
            .await
            .expect("absent token redeem")
            .is_none(),
        "redeeming an unknown token resolves to None",
    );
    assert!(
        stores
            .passkey_challenges
            .take_registration(PasskeyChallengeId::new())
            .await
            .expect("absent take registration")
            .is_none(),
        "taking an unknown registration resolves to None",
    );
    assert!(
        stores
            .passkey_challenges
            .take_authentication(PasskeyChallengeId::new())
            .await
            .expect("absent take authentication")
            .is_none(),
        "taking an unknown authentication resolves to None",
    );
}

pub(crate) async fn inserts_refuse_duplicate_keys(stores: &ExpiringStores) {
    let now = present();
    let owner = UserId::new();
    let intruder = UserId::new();

    let sessions = &stores.sessions;
    let session = |user_id, token: &str| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: days(365),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let original = session(owner, "duplicate-session");
    sessions
        .create_session(original.clone())
        .await
        .expect("create session");
    assert_refused(
        sessions
            .create_session(Session {
                id: original.id,
                ..session(intruder, "duplicate-session-other-token")
            })
            .await,
        StorageErrorKind::Conflict,
        "duplicate session id",
    );
    assert_refused(
        sessions
            .create_session(Session {
                token_hash: original.token_hash,
                transport: SessionTransport::Cookie,
                ..session(intruder, "unused")
            })
            .await,
        StorageErrorKind::Conflict,
        "duplicate session token hash",
    );
    assert_eq!(
        sessions
            .find_session_by_token_hash(&original.token_hash)
            .await
            .expect("find by hash"),
        Some(original.clone()),
        "the original session is untouched",
    );
    assert!(
        sessions
            .find_session_by_token_hash(&hash_token("duplicate-session-other-token"))
            .await
            .expect("find refused session by hash")
            .is_none(),
        "a refused session leaves no token hash behind",
    );
    assert!(
        sessions
            .list_for_user(intruder)
            .await
            .expect("list intruder")
            .is_empty(),
        "a refused session leaves nothing in its user's list",
    );

    let link = EmailLink {
        token_hash: hash_token("duplicate-link"),
        user_id: owner,
        purpose: EmailLinkPurpose::Signup,
        owner_email: None,
        new_email: None,
        created_at: now,
        expires_at: days(365),
    };
    stores
        .email_links
        .replace_link(link.clone())
        .await
        .expect("create link");
    assert_refused(
        stores
            .email_links
            .replace_link(EmailLink {
                user_id: intruder,
                purpose: EmailLinkPurpose::Recovery,
                ..link.clone()
            })
            .await,
        StorageErrorKind::Conflict,
        "duplicate email link hash",
    );
    assert_eq!(
        stores
            .email_links
            .delete_links_for_user(intruder)
            .await
            .expect("delete intruder links"),
        0,
        "a refused link leaves nothing for its user",
    );
    assert_eq!(
        stores
            .email_links
            .redeem_link(&link.token_hash)
            .await
            .expect("redeem link"),
        Some(link),
        "the original link is untouched",
    );

    let challenges = &stores.passkey_challenges;
    let registration = StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::AddPasskey,
        user_id: owner,
        state: b"duplicate-registration".to_vec(),
        owner_email: None,
        created_at: now,
        expires_at: days(365),
        recovery_cool_down_until: None,
    };
    challenges
        .put_registration(registration.clone())
        .await
        .expect("put registration");
    assert_refused(
        challenges
            .put_registration(StoredPasskeyRegistration {
                user_id: intruder,
                state: b"intruding-registration".to_vec(),
                ..registration.clone()
            })
            .await,
        StorageErrorKind::Conflict,
        "duplicate registration id",
    );
    assert!(
        challenges
            .list_registrations_for_user(intruder)
            .await
            .expect("list intruder registrations")
            .is_empty(),
        "a refused registration leaves nothing for its user",
    );
    let taken = challenges
        .take_registration(registration.id)
        .await
        .expect("take registration")
        .expect("registration present");
    assert_eq!(
        taken.user_id, owner,
        "the original registration is untouched"
    );
    assert_eq!(taken.state, registration.state);

    let authentication = StoredPasskeyAuthentication {
        id: PasskeyChallengeId::new(),
        purpose: AuthenticationPurpose::Login,
        state: b"duplicate-authentication".to_vec(),
        created_at: now,
        expires_at: days(365),
    };
    challenges
        .put_authentication(authentication.clone())
        .await
        .expect("put authentication");
    assert_refused(
        challenges
            .put_authentication(StoredPasskeyAuthentication {
                purpose: AuthenticationPurpose::Reauth,
                state: b"intruding-authentication".to_vec(),
                ..authentication.clone()
            })
            .await,
        StorageErrorKind::Conflict,
        "duplicate authentication id",
    );
    let taken = challenges
        .take_authentication(authentication.id)
        .await
        .expect("take authentication")
        .expect("authentication present");
    assert_eq!(
        taken.purpose,
        AuthenticationPurpose::Login,
        "the original authentication is untouched",
    );
    assert_eq!(taken.state, authentication.state);
}
