//! Backend-agnostic storage-conformance suite.
//!
//! Every check takes a [`Storage`] and asserts the contract the
//! `bauth-core` managers rely on, independent of how the rows are stored.
//! The same [`run`] entry point is executed against the in-memory
//! reference stores (`tests/in_memory.rs`), SQLite (`tests/sqlite.rs`),
//! and Postgres (`tests/postgres.rs`, gated on `PG_URL`). Running the
//! identical assertions everywhere closes the gap that previously let the
//! two SQLx adapters drift apart, and pins the in-memory stores to the
//! same contract the docs claim they model.
//!
//! Checks share a single `Storage` instance, so each uses freshly minted
//! ids and token hashes to stay isolated; assertions that touch
//! whole-table operations (`purge_expired`) target a specific row rather
//! than an exact count.

#![allow(dead_code)]

use bauth_core::session::hash_token;
use bauth_core::storage::{
    PasskeyChallengeId, PasskeySummary, Session, SessionId, Storage, StoredPasskey,
    StoredPasskeyRegistration, User, UserId, VerificationPurpose, VerificationToken,
};
use chrono::{DateTime, Duration, TimeZone, Utc};

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

/// Run the full suite against `storage`.
pub async fn run(storage: &Storage) {
    users_round_trip(storage).await;
    verification_token_single_use(storage).await;
    verification_token_purge_and_delete(storage).await;
    sessions_crud_and_queries(storage).await;
    sessions_purge_expired(storage).await;
    passkey_credentials_cooldown_round_trip(storage).await;
    passkey_registration_cooldown_round_trip(storage).await;
    passkey_registration_delete_for_user(storage).await;
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
    let listed = sessions.list_for_user(user_id).await.expect("list");
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
    let after = sessions.list_for_user(user_id).await.expect("list after");
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
            .list_for_user(user_id)
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
    // opaque bytes: it persists whatever bauth-core hands it and returns it
    // verbatim, with no webauthn-rs knowledge of its own.
    let credential_id = b"conformance-credential-id".to_vec();
    let passkey_blob = b"opaque-serialised-passkey-blob".to_vec();
    let cooldown_until = now + Duration::hours(24);
    let credential = StoredPasskey {
        credential_id: credential_id.clone(),
        user_id,
        passkey: passkey_blob.clone(),
        name: Some("security key".into()),
        created_at: now,
        last_used_at: None,
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
    assert_eq!(by_id.recovery_cooldown_until, Some(cooldown_until));

    let updated_cooldown_until = now + Duration::hours(48);
    let updated_blob = b"opaque-serialised-passkey-blob-v2".to_vec();
    let updated = StoredPasskey {
        passkey: updated_blob.clone(),
        name: Some("renamed security key".into()),
        last_used_at: Some(now + Duration::minutes(5)),
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
