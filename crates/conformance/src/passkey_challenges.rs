use chrono::Duration;
use doorman_core::storage::{
    AuthenticationPurpose, ExpiringStores, PasskeyChallengeId, RegistrationPurpose,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, UserId,
};

use crate::fixtures::{RACERS, REVOKE_ROUNDS, days, present};

pub(crate) async fn passkey_registration_round_trip(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let state_blob = b"opaque-serialised-registration-state".to_vec();
    let cool_down_until = now + Duration::hours(24);
    for purpose in [
        RegistrationPurpose::Signup,
        RegistrationPurpose::Recovery,
        RegistrationPurpose::AddPasskey,
    ] {
        let challenge_id = PasskeyChallengeId::new();
        let owner_email =
            (purpose != RegistrationPurpose::AddPasskey).then(|| "owner@example.com".to_string());
        stores
            .passkey_challenges
            .put_registration(StoredPasskeyRegistration {
                id: challenge_id,
                purpose,
                user_id,
                state: state_blob.clone(),
                owner_email: owner_email.clone(),
                created_at: now,
                expires_at: now + Duration::minutes(5),
                recovery_cool_down_until: Some(cool_down_until),
            })
            .await
            .expect("put registration");

        let taken = stores
            .passkey_challenges
            .take_registration(challenge_id)
            .await
            .expect("take registration")
            .expect("registration present");
        assert_eq!(taken.id, challenge_id);
        assert_eq!(taken.purpose, purpose, "purpose round-trips verbatim");
        assert_eq!(taken.user_id, user_id);
        assert_eq!(taken.created_at, now);
        assert_eq!(taken.expires_at, now + Duration::minutes(5));
        assert_eq!(taken.recovery_cool_down_until, Some(cool_down_until));
        assert_eq!(
            taken.owner_email, owner_email,
            "owner's address round-trips"
        );
        assert_eq!(
            taken.state, state_blob,
            "ceremony blob round-trips verbatim"
        );
        assert!(
            stores
                .passkey_challenges
                .take_registration(challenge_id)
                .await
                .expect("second take")
                .is_none(),
            "registration challenges are single-use",
        );
    }
}

pub(crate) async fn passkey_registration_delete_for_user(stores: &ExpiringStores) {
    let now = present();
    let target = UserId::new();
    let bystander = UserId::new();

    let put = |user_id: UserId| {
        let challenge_id = PasskeyChallengeId::new();
        async move {
            stores
                .passkey_challenges
                .put_registration(StoredPasskeyRegistration {
                    id: challenge_id,
                    purpose: RegistrationPurpose::AddPasskey,
                    user_id,
                    state: b"opaque-state".to_vec(),
                    owner_email: None,
                    created_at: now,
                    expires_at: now + Duration::minutes(5),
                    recovery_cool_down_until: None,
                })
                .await
                .expect("put registration");
            challenge_id
        }
    };

    let _target_a = put(target).await;
    let _target_b = put(target).await;
    let bystander_challenge = put(bystander).await;

    assert_eq!(
        stores
            .passkey_challenges
            .list_registrations_for_user(target)
            .await
            .expect("count target")
            .len(),
        2,
        "target has two pending registrations",
    );
    assert_eq!(
        stores
            .passkey_challenges
            .list_registrations_for_user(bystander)
            .await
            .expect("count bystander")
            .len(),
        1,
    );

    let dropped = stores
        .passkey_challenges
        .delete_registrations_for_user(target)
        .await
        .expect("delete registrations");
    assert_eq!(
        dropped, 2,
        "both of the target's pending challenges removed"
    );

    assert_eq!(
        stores
            .passkey_challenges
            .list_registrations_for_user(target)
            .await
            .expect("count target after delete")
            .len(),
        0,
        "count drops to zero after the user's challenges are deleted",
    );

    assert_eq!(
        stores
            .passkey_challenges
            .list_registrations_for_user(bystander)
            .await
            .expect("count bystander after delete")
            .len(),
        1,
        "another user's pending registration must be untouched",
    );
    assert!(
        stores
            .passkey_challenges
            .take_registration(bystander_challenge)
            .await
            .expect("take bystander")
            .is_some(),
        "another user's pending registration must be untouched",
    );

    let dropped_again = stores
        .passkey_challenges
        .delete_registrations_for_user(target)
        .await
        .expect("second delete");
    assert_eq!(dropped_again, 0);
}

pub(crate) async fn passkey_registration_delete_races_creation(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let registration = || StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::AddPasskey,
        user_id,
        state: b"opaque-state".to_vec(),
        owner_email: None,
        created_at: now,
        expires_at: days(1),
        recovery_cool_down_until: None,
    };
    let put = |registration: StoredPasskeyRegistration| {
        let challenges = stores.passkey_challenges.clone();
        tokio::spawn(async move {
            challenges
                .put_registration(registration)
                .await
                .expect("put registration");
        })
    };

    let mut put_ids = Vec::new();
    for _ in 0..REVOKE_ROUNDS {
        let batch: Vec<StoredPasskeyRegistration> = (0..RACERS).map(|_| registration()).collect();
        let (before, after) = batch.split_at(RACERS / 2);
        let mut tasks: Vec<_> = before.iter().cloned().map(put).collect();
        let challenges = stores.passkey_challenges.clone();
        tasks.push(tokio::spawn(async move {
            challenges
                .delete_registrations_for_user(user_id)
                .await
                .expect("delete registrations");
        }));
        tasks.extend(after.iter().cloned().map(put));
        for task in tasks {
            task.await.expect("race task");
        }
        put_ids.extend(batch.iter().map(|r| r.id));
    }

    let listed = stores
        .passkey_challenges
        .list_registrations_for_user(user_id)
        .await
        .expect("list")
        .len();
    let removed = stores
        .passkey_challenges
        .delete_registrations_for_user(user_id)
        .await
        .expect("second delete");
    assert_eq!(
        removed, listed as u64,
        "the second delete removes every listed survivor",
    );
    for id in put_ids {
        assert!(
            stores
                .passkey_challenges
                .take_registration(id)
                .await
                .expect("take after second delete")
                .is_none(),
            "no registration survives the second delete",
        );
    }
}

pub(crate) async fn passkey_authentication_single_use(stores: &ExpiringStores) {
    let now = present();
    for purpose in [AuthenticationPurpose::Login, AuthenticationPurpose::Reauth] {
        let challenge_id = PasskeyChallengeId::new();
        let state_blob = b"opaque-serialised-authentication-state".to_vec();
        stores
            .passkey_challenges
            .put_authentication(StoredPasskeyAuthentication {
                id: challenge_id,
                purpose,
                state: state_blob.clone(),
                created_at: now,
                expires_at: now + Duration::minutes(5),
            })
            .await
            .expect("put authentication");

        let taken = stores
            .passkey_challenges
            .take_authentication(challenge_id)
            .await
            .expect("take authentication")
            .expect("authentication present");
        assert_eq!(taken.id, challenge_id);
        assert_eq!(taken.purpose, purpose, "purpose round-trips verbatim");
        assert_eq!(taken.created_at, now);
        assert_eq!(taken.expires_at, now + Duration::minutes(5));
        assert_eq!(
            taken.state, state_blob,
            "ceremony blob round-trips verbatim"
        );
        assert!(
            stores
                .passkey_challenges
                .take_authentication(challenge_id)
                .await
                .expect("second take")
                .is_none(),
            "authentication challenges are single-use",
        );
    }
}

pub(crate) async fn passkey_challenge_purge_expired(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let challenges = &stores.passkey_challenges;
    let expired_registration = PasskeyChallengeId::new();
    challenges
        .put_registration(StoredPasskeyRegistration {
            id: expired_registration,
            purpose: RegistrationPurpose::AddPasskey,
            user_id,
            state: b"expired-registration".to_vec(),
            owner_email: None,
            created_at: days(-2),
            expires_at: days(-1),
            recovery_cool_down_until: None,
        })
        .await
        .expect("put expired registration");
    let expired_authentication = PasskeyChallengeId::new();
    challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: expired_authentication,
            purpose: AuthenticationPurpose::Login,
            state: b"expired-authentication".to_vec(),
            created_at: days(-2),
            expires_at: days(-1),
        })
        .await
        .expect("put expired authentication");
    let live_registration = PasskeyChallengeId::new();
    challenges
        .put_registration(StoredPasskeyRegistration {
            id: live_registration,
            purpose: RegistrationPurpose::AddPasskey,
            user_id,
            state: b"live-registration".to_vec(),
            owner_email: None,
            created_at: now,
            expires_at: days(365),
            recovery_cool_down_until: None,
        })
        .await
        .expect("put live registration");

    let purged = challenges.purge_expired(now).await.expect("purge");
    assert!(purged >= 2, "both expired challenges were purged");
    assert!(
        challenges
            .take_registration(expired_registration)
            .await
            .expect("take expired registration")
            .is_none(),
        "the expired registration was removed by purge_expired",
    );
    assert!(
        challenges
            .take_authentication(expired_authentication)
            .await
            .expect("take expired authentication")
            .is_none(),
        "the expired authentication was removed by purge_expired",
    );
    assert!(
        challenges
            .take_registration(live_registration)
            .await
            .expect("take live registration")
            .is_some(),
        "the live registration survived the purge",
    );
}
