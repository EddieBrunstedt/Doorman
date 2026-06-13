//! Backend-agnostic storage-conformance suite for doorman storage adapters.
//!
//! Every check takes a [`Storage`] and asserts the contract the
//! `doorman-core` managers rely on, independent of how the rows are stored.
//! Depend on this crate under `[dev-dependencies]` and call [`run`] from a
//! test to validate any adapter against the same assertions every first-party
//! adapter runs (`doorman-sqlx` across SQLite/Postgres/MySQL plus the
//! in-memory reference stores, `doorman-redis`, `doorman-dynamodb`,
//! `doorman-mongodb`, and `doorman-redb`). Running the identical assertions
//! everywhere keeps adapters from drifting apart and pins the in-memory
//! stores to the same contract the docs claim they model.
//!
//! [`run_db_backed`] adds the extra assertions that only hold for adapters
//! which push the expiry predicate into their query layer; call it in addition
//! to [`run`] from those harnesses.
//!
//! Checks share a single `Storage` instance, so each uses freshly minted
//! ids and token hashes to stay isolated; assertions that touch
//! whole-table operations (`purge_expired`) target a specific row rather
//! than an exact count.

use chrono::{DateTime, Duration, TimeZone, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    PasskeyChallengeId, PasskeySummary, Session, SessionId, Storage, StoredPasskey,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId, VerificationPurpose,
    VerificationToken,
};

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn user(id: UserId, email: &str) -> User {
    User {
        id,
        email: Some(email.to_string()),
        email_verified_at: None,
        created_at: ts(2026, 1, 1),
        updated_at: ts(2026, 1, 1),
    }
}

/// Run the full backend-agnostic suite against `storage`.
pub async fn run(storage: &Storage) {
    users_round_trip(storage).await;
    verification_token_single_use(storage).await;
    verification_token_email_change_payload(storage).await;
    verification_token_purge_and_delete(storage).await;
    sessions_crud_and_queries(storage).await;
    sessions_purge_expired(storage).await;
    passkey_credentials_cooldown_round_trip(storage).await;
    passkey_registration_cooldown_round_trip(storage).await;
    passkey_registration_delete_for_user(storage).await;
    passkey_authentication_single_use(storage).await;
    passkey_challenge_purge_expired(storage).await;
    absent_lookups_return_none(storage).await;
}

/// Extra assertions that only hold for database-backed adapters, which push
/// the expiry predicate into the query (or filter on read). The in-memory
/// reference store deliberately returns expired rows (the manager filters
/// them), so every adapter harness calls this in addition to [`run`] while
/// the in-memory harness sticks to [`run`] alone.
pub async fn run_db_backed(storage: &Storage) {
    sessions_list_excludes_expired(storage).await;
}

/// `SessionStore::list_for_user` must drop rows whose `expires_at <= now`
/// before they leave the database.
async fn sessions_list_excludes_expired(storage: &Storage) {
    let now = ts(2026, 3, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "list-expiry@example.com"))
        .await
        .expect("user");

    let mk = |token: &str, expires_at: DateTime<Utc>| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        created_at: now - Duration::hours(2),
        expires_at,
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    let live = mk("list-live", now + Duration::hours(1));
    let expired = mk("list-expired", now - Duration::hours(1));
    for session in [&live, &expired] {
        storage
            .sessions
            .create_session(session.clone())
            .await
            .expect("create session");
    }

    let listed = storage
        .sessions
        .list_for_user(user_id, now)
        .await
        .expect("list");
    let ids: std::collections::HashSet<_> = listed.iter().map(|s| s.id).collect();
    assert!(ids.contains(&live.id), "live session is listed");
    assert!(
        !ids.contains(&expired.id),
        "expired session is excluded at the store"
    );
}

async fn users_round_trip(storage: &Storage) {
    let users = &storage.users;
    let id = UserId::new();
    let record = user(id, "round-trip@example.com");
    users.create_user(record.clone()).await.expect("create");

    assert_eq!(
        users.find_user_by_id(id).await.expect("find by id"),
        Some(record.clone()),
    );
    assert_eq!(
        users
            .find_user_by_email("round-trip@example.com")
            .await
            .expect("find by email"),
        Some(record.clone()),
    );

    // Duplicate id is rejected.
    users
        .create_user(user(id, "different@example.com"))
        .await
        .expect_err("duplicate id should error");
    // Duplicate email is rejected.
    users
        .create_user(user(UserId::new(), "round-trip@example.com"))
        .await
        .expect_err("duplicate email should error");

    // Update is observable.
    let verified = User {
        email_verified_at: Some(ts(2026, 2, 1)),
        updated_at: ts(2026, 2, 1),
        ..record
    };
    users.update_user(verified.clone()).await.expect("update");
    assert_eq!(
        users.find_user_by_id(id).await.expect("find updated"),
        Some(verified),
    );

    // Delete removes both lookups.
    users.delete_user(id).await.expect("delete");
    assert!(
        users
            .find_user_by_id(id)
            .await
            .expect("find after delete")
            .is_none()
    );
    assert!(
        users
            .find_user_by_email("round-trip@example.com")
            .await
            .expect("find email after delete")
            .is_none()
    );
}

async fn verification_token_single_use(storage: &Storage) {
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "single-use@example.com"))
        .await
        .expect("user");

    let tokens = &storage.verification_tokens;
    let hash = hash_token("single-use-token");
    tokens
        .create_token(VerificationToken {
            token_hash: hash,
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create");

    assert!(
        tokens
            .consume_token(&hash, VerificationPurpose::Signup)
            .await
            .expect("first consume")
            .is_some(),
        "first consume returns the token",
    );
    assert!(
        tokens
            .consume_token(&hash, VerificationPurpose::Signup)
            .await
            .expect("second consume")
            .is_none(),
        "second consume returns nothing",
    );

    // A token of one purpose cannot be redeemed under another.
    let signup_hash = hash_token("purpose-scoped-token");
    tokens
        .create_token(VerificationToken {
            token_hash: signup_hash,
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create scoped");
    assert!(
        tokens
            .consume_token(&signup_hash, VerificationPurpose::Recovery)
            .await
            .expect("wrong-purpose consume")
            .is_none(),
        "consuming under the wrong purpose returns nothing",
    );
    assert!(
        tokens
            .consume_token(&signup_hash, VerificationPurpose::Signup)
            .await
            .expect("right-purpose consume")
            .is_some(),
        "the token still redeems under its own purpose",
    );
}

/// An email-change token carries the target address in `new_email`; it must
/// round-trip through `create`/`consume` so the confirm step can read it back.
async fn verification_token_email_change_payload(storage: &Storage) {
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "email-change@example.com"))
        .await
        .expect("user");

    let tokens = &storage.verification_tokens;
    let hash = hash_token("email-change-token");
    tokens
        .create_token(VerificationToken {
            token_hash: hash,
            user_id,
            purpose: VerificationPurpose::EmailChange,
            new_email: Some("new-address@example.com".to_string()),
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create email-change token");

    let consumed = tokens
        .consume_token(&hash, VerificationPurpose::EmailChange)
        .await
        .expect("consume")
        .expect("token present");
    assert_eq!(consumed.purpose, VerificationPurpose::EmailChange);
    assert_eq!(
        consumed.new_email.as_deref(),
        Some("new-address@example.com"),
        "the target address round-trips through storage",
    );
}

async fn verification_token_purge_and_delete(storage: &Storage) {
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "purge-tokens@example.com"))
        .await
        .expect("user");

    let tokens = &storage.verification_tokens;
    let signup_hash = hash_token("delete-signup");
    let recovery_hash = hash_token("delete-recovery");
    tokens
        .create_token(VerificationToken {
            token_hash: signup_hash,
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create signup");
    tokens
        .create_token(VerificationToken {
            token_hash: recovery_hash,
            user_id,
            purpose: VerificationPurpose::Recovery,
            new_email: None,
            created_at: ts(2026, 1, 1),
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create recovery");

    // Deleting one purpose leaves the other intact.
    let removed = tokens
        .delete_tokens_for_user(user_id, VerificationPurpose::Signup)
        .await
        .expect("delete signup tokens");
    assert_eq!(removed, 1, "exactly the signup token was deleted");
    assert!(
        tokens
            .consume_token(&signup_hash, VerificationPurpose::Signup)
            .await
            .expect("consume deleted")
            .is_none(),
        "the deleted signup token no longer redeems",
    );
    assert!(
        tokens
            .consume_token(&recovery_hash, VerificationPurpose::Recovery)
            .await
            .expect("consume surviving")
            .is_some(),
        "the recovery token of another purpose survived the delete",
    );

    // An expired token is purged; a live one is not.
    let expired_hash = hash_token("expired-token");
    tokens
        .create_token(VerificationToken {
            token_hash: expired_hash,
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: ts(2020, 1, 1),
            expires_at: ts(2020, 1, 2),
        })
        .await
        .expect("create expired");
    let purged = tokens.purge_expired(ts(2026, 1, 1)).await.expect("purge");
    assert!(purged >= 1, "at least the expired token was purged");
    assert!(
        tokens
            .consume_token(&expired_hash, VerificationPurpose::Signup)
            .await
            .expect("consume purged")
            .is_none(),
        "the expired token was removed by purge_expired",
    );
}

async fn sessions_crud_and_queries(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    let other_user = UserId::new();
    storage
        .users
        .create_user(user(user_id, "sessions@example.com"))
        .await
        .expect("user");
    storage
        .users
        .create_user(user(other_user, "neighbour@example.com"))
        .await
        .expect("other user");

    let sessions = &storage.sessions;
    let mk = |token: &str, owner: UserId, cooldown: Option<DateTime<Utc>>| Session {
        id: SessionId::new(),
        user_id: owner,
        token_hash: hash_token(token),
        created_at: now,
        expires_at: now + Duration::hours(1),
        ip: Some("203.0.113.1".into()),
        user_agent: Some("agent".into()),
        recovery_cooldown_until: cooldown,
    };

    let keep = mk("keep", user_id, None);
    let other_a = mk("other-a", user_id, None);
    let other_b = mk("other-b", user_id, None);
    let neighbour = mk("neighbour", other_user, None);
    // Recovery-issued session carries a cool-down instant that must survive
    // the round-trip through storage.
    let cooldown_until = now + Duration::hours(24);
    let with_cooldown = mk("cooldown", user_id, Some(cooldown_until));

    for session in [&keep, &other_a, &other_b, &neighbour, &with_cooldown] {
        sessions
            .create_session(session.clone())
            .await
            .expect("create session");
    }

    // find_session_by_token_hash round-trips the row, cool-down included.
    let by_hash = sessions
        .find_session_by_token_hash(&hash_token("cooldown"))
        .await
        .expect("find by hash")
        .expect("session present");
    assert_eq!(by_hash.id, with_cooldown.id);
    assert_eq!(by_hash.recovery_cooldown_until, Some(cooldown_until));
    assert_eq!(by_hash.ip.as_deref(), Some("203.0.113.1"));

    let by_id = sessions
        .find_session_by_id(with_cooldown.id)
        .await
        .expect("find by id")
        .expect("session present");
    assert_eq!(by_id.recovery_cooldown_until, Some(cooldown_until));

    // list_for_user returns every (unexpired) session for the user.
    let listed = sessions.list_for_user(user_id, now).await.expect("list");
    let listed_ids: std::collections::HashSet<_> = listed.iter().map(|s| s.id).collect();
    let expected: std::collections::HashSet<_> =
        [keep.id, other_a.id, other_b.id, with_cooldown.id].into();
    assert_eq!(
        listed_ids, expected,
        "list returns only this user's sessions"
    );

    // delete_other_sessions_for_user keeps the exception, removes the rest.
    let removed = sessions
        .delete_other_sessions_for_user(user_id, keep.id)
        .await
        .expect("delete others");
    assert_eq!(removed, 3, "every session except the exception was removed");
    let after = sessions
        .list_for_user(user_id, now)
        .await
        .expect("list after");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, keep.id);

    // The neighbouring user's session is untouched.
    assert!(
        sessions
            .find_session_by_id(neighbour.id)
            .await
            .expect("find neighbour")
            .is_some()
    );

    // delete_sessions_for_user clears the rest for this user.
    let removed = sessions
        .delete_sessions_for_user(user_id)
        .await
        .expect("delete all");
    assert_eq!(removed, 1, "the surviving session was removed");
    assert!(
        sessions
            .list_for_user(user_id, now)
            .await
            .expect("list cleared")
            .is_empty()
    );
    // delete_session on the neighbour's row.
    sessions
        .delete_session(neighbour.id)
        .await
        .expect("delete neighbour");
    assert!(
        sessions
            .find_session_by_id(neighbour.id)
            .await
            .expect("find deleted neighbour")
            .is_none()
    );
}

async fn sessions_purge_expired(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "purge-sessions@example.com"))
        .await
        .expect("user");

    let sessions = &storage.sessions;
    let expired = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("expired-session"),
        created_at: now - Duration::hours(2),
        expires_at: now - Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    let live = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("live-session"),
        created_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    sessions
        .create_session(expired.clone())
        .await
        .expect("create expired");
    sessions
        .create_session(live.clone())
        .await
        .expect("create live");

    let removed = sessions.purge_expired(now).await.expect("purge");
    assert!(removed >= 1, "at least the expired session was purged");
    assert!(
        sessions
            .find_session_by_id(expired.id)
            .await
            .expect("find expired")
            .is_none(),
        "the expired session was purged",
    );
    assert!(
        sessions
            .find_session_by_id(live.id)
            .await
            .expect("find live")
            .is_some(),
        "the live session survived the purge",
    );
}

async fn passkey_credentials_cooldown_round_trip(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "passkey-round-trip@example.com"))
        .await
        .expect("user");

    // The store treats both the credential id and the credential blob as
    // opaque bytes: it persists whatever doorman-core hands it and returns it
    // verbatim, with no webauthn-rs knowledge of its own.
    let credential_id = b"conformance-credential-id".to_vec();
    let passkey_blob = b"opaque-serialised-passkey-blob".to_vec();
    let cooldown_until = now + Duration::hours(24);
    let aaguid = uuid::Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
    let credential = StoredPasskey {
        credential_id: credential_id.clone(),
        user_id,
        passkey: passkey_blob.clone(),
        name: Some("security key".into()),
        created_at: now,
        last_used_at: None,
        aaguid: Some(aaguid),
        transports: vec!["usb".into(), "nfc".into()],
        backup_eligible: false,
        backup_state: false,
        recovery_cooldown_until: Some(cooldown_until),
    };

    let credentials = &storage.passkey_credentials;
    credentials
        .add_passkey(credential.clone())
        .await
        .expect("create passkey");

    let by_id = credentials
        .find_passkey_by_credential_id(&credential.credential_id)
        .await
        .expect("find by credential id")
        .expect("passkey present");
    assert_eq!(by_id.user_id, user_id);
    assert_eq!(by_id.name.as_deref(), Some("security key"));
    assert_eq!(by_id.passkey, passkey_blob, "blob round-trips verbatim");
    assert_eq!(by_id.aaguid, Some(aaguid), "aaguid round-trips");
    assert_eq!(by_id.transports, vec!["usb".to_string(), "nfc".to_string()]);
    assert!(!by_id.backup_eligible);
    assert!(!by_id.backup_state);
    assert_eq!(by_id.recovery_cooldown_until, Some(cooldown_until));

    let updated_cooldown_until = now + Duration::hours(48);
    let updated_blob = b"opaque-serialised-passkey-blob-v2".to_vec();
    let updated = StoredPasskey {
        passkey: updated_blob.clone(),
        name: Some("renamed security key".into()),
        last_used_at: Some(now + Duration::minutes(5)),
        // The credential became backed up after registration: the update
        // must persist the refreshed flags and the (now single) transport.
        transports: vec!["internal".into()],
        backup_eligible: true,
        backup_state: true,
        recovery_cooldown_until: Some(updated_cooldown_until),
        ..by_id
    };
    credentials
        .update_passkey(updated.clone())
        .await
        .expect("update passkey");

    let listed = credentials
        .list_passkeys_for_user(user_id)
        .await
        .expect("list passkeys");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].credential_id, updated.credential_id);
    assert_eq!(listed[0].passkey, updated_blob, "updated blob round-trips");
    assert_eq!(listed[0].name.as_deref(), Some("renamed security key"));
    assert_eq!(listed[0].last_used_at, updated.last_used_at);
    assert_eq!(listed[0].aaguid, Some(aaguid), "aaguid preserved on update");
    assert_eq!(listed[0].transports, vec!["internal".to_string()]);
    assert!(
        listed[0].backup_eligible,
        "backup flags refreshed on update"
    );
    assert!(listed[0].backup_state);
    assert_eq!(
        listed[0].recovery_cooldown_until,
        Some(updated_cooldown_until),
    );

    // The metadata-only projection carries the same fields as the full
    // record, derived without deserialising the credential blob.
    let summaries = credentials
        .list_passkey_summaries_for_user(user_id)
        .await
        .expect("list passkey summaries");
    assert_eq!(summaries.len(), 1);
    let summary = &summaries[0];
    assert_eq!(summary.credential_id, updated.credential_id);
    assert_eq!(summary.user_id, user_id);
    assert_eq!(summary.name.as_deref(), Some("renamed security key"));
    assert_eq!(summary.created_at, updated.created_at);
    assert_eq!(summary.last_used_at, updated.last_used_at);
    assert_eq!(summary.aaguid, Some(aaguid));
    assert_eq!(summary.transports, vec!["internal".to_string()]);
    assert!(summary.backup_eligible);
    assert!(summary.backup_state);
    assert_eq!(
        summary.recovery_cooldown_until,
        Some(updated_cooldown_until)
    );
    // The same record viewed as a summary is byte-for-byte the projection.
    assert_eq!(*summary, PasskeySummary::from(listed[0].clone()));
}

async fn passkey_registration_cooldown_round_trip(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "registration-round-trip@example.com"))
        .await
        .expect("user");

    // The ceremony state is opaque to the store: an arbitrary byte blob must
    // survive the round-trip through `put`/`take` unchanged.
    let state_blob = b"opaque-serialised-registration-state".to_vec();
    let cooldown_until = now + Duration::hours(24);
    let challenge_id = PasskeyChallengeId::new();
    storage
        .passkey_challenges
        .put_registration(StoredPasskeyRegistration {
            id: challenge_id,
            user_id,
            state: state_blob.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(5),
            recovery_cooldown_until: Some(cooldown_until),
        })
        .await
        .expect("put registration");

    let taken = storage
        .passkey_challenges
        .take_registration(challenge_id)
        .await
        .expect("take registration")
        .expect("registration present");
    assert_eq!(taken.id, challenge_id);
    assert_eq!(taken.user_id, user_id);
    assert_eq!(taken.created_at, now);
    assert_eq!(taken.expires_at, now + Duration::minutes(5));
    assert_eq!(taken.recovery_cooldown_until, Some(cooldown_until));
    assert_eq!(
        taken.state, state_blob,
        "ceremony blob round-trips verbatim"
    );
    assert!(
        storage
            .passkey_challenges
            .take_registration(challenge_id)
            .await
            .expect("second take")
            .is_none(),
        "registration challenges are single-use",
    );
}

/// `delete_registrations_for_user` drops every pending registration for the
/// target user and leaves other users' challenges untouched. Recovery
/// completion relies on this to close the pre-recovery-challenge bypass.
async fn passkey_registration_delete_for_user(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let target = UserId::new();
    let bystander = UserId::new();
    storage
        .users
        .create_user(user(target, "delete-regs-target@example.com"))
        .await
        .expect("target user");
    storage
        .users
        .create_user(user(bystander, "delete-regs-bystander@example.com"))
        .await
        .expect("bystander user");

    let put = |user_id: UserId| {
        let challenge_id = PasskeyChallengeId::new();
        async move {
            storage
                .passkey_challenges
                .put_registration(StoredPasskeyRegistration {
                    id: challenge_id,
                    user_id,
                    state: b"opaque-state".to_vec(),
                    created_at: now,
                    expires_at: now + Duration::minutes(5),
                    recovery_cooldown_until: None,
                })
                .await
                .expect("put registration");
            challenge_id
        }
    };

    let _target_a = put(target).await;
    let _target_b = put(target).await;
    let bystander_challenge = put(bystander).await;

    // The per-user count backs the pending-registration cap and must scope to
    // the user it is asked about.
    assert_eq!(
        storage
            .passkey_challenges
            .count_registrations_for_user(target)
            .await
            .expect("count target"),
        2,
        "target has two pending registrations",
    );
    assert_eq!(
        storage
            .passkey_challenges
            .count_registrations_for_user(bystander)
            .await
            .expect("count bystander"),
        1,
    );

    let dropped = storage
        .passkey_challenges
        .delete_registrations_for_user(target)
        .await
        .expect("delete registrations");
    assert_eq!(
        dropped, 2,
        "both of the target's pending challenges removed"
    );

    assert_eq!(
        storage
            .passkey_challenges
            .count_registrations_for_user(target)
            .await
            .expect("count target after delete"),
        0,
        "count drops to zero after the user's challenges are deleted",
    );

    // The bystander's challenge survives.
    assert_eq!(
        storage
            .passkey_challenges
            .count_registrations_for_user(bystander)
            .await
            .expect("count bystander after delete"),
        1,
        "another user's pending registration must be untouched",
    );
    assert!(
        storage
            .passkey_challenges
            .take_registration(bystander_challenge)
            .await
            .expect("take bystander")
            .is_some(),
        "another user's pending registration must be untouched",
    );

    // A second delete is a no-op.
    let dropped_again = storage
        .passkey_challenges
        .delete_registrations_for_user(target)
        .await
        .expect("second delete");
    assert_eq!(dropped_again, 0);
}

/// An authentication ceremony round-trips its opaque state through
/// `put`/`take` and is single-use: `take_authentication` removes the challenge
/// before returning it, so a second take observes nothing. Authentications are
/// not user-scoped, so unlike registrations they carry no secondary index.
async fn passkey_authentication_single_use(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let challenge_id = PasskeyChallengeId::new();
    let state_blob = b"opaque-serialised-authentication-state".to_vec();
    storage
        .passkey_challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: challenge_id,
            state: state_blob.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(5),
        })
        .await
        .expect("put authentication");

    let taken = storage
        .passkey_challenges
        .take_authentication(challenge_id)
        .await
        .expect("take authentication")
        .expect("authentication present");
    assert_eq!(taken.id, challenge_id);
    assert_eq!(taken.created_at, now);
    assert_eq!(taken.expires_at, now + Duration::minutes(5));
    assert_eq!(
        taken.state, state_blob,
        "ceremony blob round-trips verbatim"
    );
    assert!(
        storage
            .passkey_challenges
            .take_authentication(challenge_id)
            .await
            .expect("second take")
            .is_none(),
        "authentication challenges are single-use",
    );
}

/// `PasskeyChallengeStore::purge_expired` drops expired ceremonies and spares
/// live ones, across both ceremony kinds: a registration (reached through its
/// per-user index) and an authentication (no index, reached by row scan).
async fn passkey_challenge_purge_expired(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "purge-challenges@example.com"))
        .await
        .expect("user");

    let challenges = &storage.passkey_challenges;
    let expired_registration = PasskeyChallengeId::new();
    challenges
        .put_registration(StoredPasskeyRegistration {
            id: expired_registration,
            user_id,
            state: b"expired-registration".to_vec(),
            created_at: ts(2020, 1, 1),
            expires_at: ts(2020, 1, 2),
            recovery_cooldown_until: None,
        })
        .await
        .expect("put expired registration");
    let expired_authentication = PasskeyChallengeId::new();
    challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: expired_authentication,
            state: b"expired-authentication".to_vec(),
            created_at: ts(2020, 1, 1),
            expires_at: ts(2020, 1, 2),
        })
        .await
        .expect("put expired authentication");
    let live_registration = PasskeyChallengeId::new();
    challenges
        .put_registration(StoredPasskeyRegistration {
            id: live_registration,
            user_id,
            state: b"live-registration".to_vec(),
            created_at: now,
            expires_at: ts(2099, 1, 1),
            recovery_cooldown_until: None,
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

/// Looking up an id or token that was never stored resolves to `None` rather
/// than erroring, on every read and take path the managers depend on.
async fn absent_lookups_return_none(storage: &Storage) {
    assert!(
        storage
            .sessions
            .find_session_by_id(SessionId::new())
            .await
            .expect("absent session by id")
            .is_none(),
        "an unknown session id resolves to None",
    );
    assert!(
        storage
            .sessions
            .find_session_by_token_hash(&hash_token("no-such-session"))
            .await
            .expect("absent session by hash")
            .is_none(),
        "an unknown session token hash resolves to None",
    );
    assert!(
        storage
            .verification_tokens
            .consume_token(&hash_token("no-such-token"), VerificationPurpose::Signup)
            .await
            .expect("absent token consume")
            .is_none(),
        "consuming an unknown token resolves to None",
    );
    assert!(
        storage
            .passkey_challenges
            .take_registration(PasskeyChallengeId::new())
            .await
            .expect("absent take registration")
            .is_none(),
        "taking an unknown registration resolves to None",
    );
    assert!(
        storage
            .passkey_challenges
            .take_authentication(PasskeyChallengeId::new())
            .await
            .expect("absent take authentication")
            .is_none(),
        "taking an unknown authentication resolves to None",
    );
}
