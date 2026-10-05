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
//!
//! The concurrency checks spawn tasks, so the suite must be awaited inside a
//! Tokio runtime (`#[tokio::test]` is enough). Under a multi-thread runtime
//! the racing callers also run in parallel.

use std::future::Future;

use chrono::{DateTime, Duration, TimeZone, Utc};
use doorman_core::error::{StorageErrorKind, StorageResult};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AccountStatus, AuthenticationPurpose, PasskeyChallengeId, PasskeySummary, PasskeyUse, Session,
    SessionId, Storage, StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration,
    User, UserId, VerificationPurpose, VerificationToken,
};

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

/// Assert `result` failed with `kind`; `what` names the refused operation.
#[track_caller]
fn assert_refused<T: std::fmt::Debug>(
    result: StorageResult<T>,
    kind: StorageErrorKind,
    what: &str,
) {
    match result {
        Err(err) => assert_eq!(err.kind(), kind, "{what}: wrong error kind ({err})"),
        Ok(value) => panic!("{what}: expected {kind:?}, got Ok({value:?})"),
    }
}

fn user(id: UserId, email: &str) -> User {
    User {
        id,
        email: Some(email.to_string()),
        email_verified_at: None,
        status: AccountStatus::Active,
        created_at: ts(2026, 1, 1),
        updated_at: ts(2026, 1, 1),
    }
}

/// Number of concurrent callers racing to redeem one single-use row.
const RACERS: usize = 64;

/// Run the full backend-agnostic suite against `storage`.
///
/// Must be awaited inside a Tokio runtime; see the crate docs.
pub async fn run(storage: &Storage) {
    users_round_trip(storage).await;
    users_email_change(storage).await;
    users_field_changes_compose(storage).await;
    users_setters_refuse_missing_user(storage).await;
    verification_token_single_use(storage).await;
    verification_token_email_change_payload(storage).await;
    verification_token_purge_and_delete(storage).await;
    sessions_crud_and_queries(storage).await;
    sessions_purge_expired(storage).await;
    session_touch_slides_deadline(storage).await;
    session_touch_does_not_resurrect(storage).await;
    session_revoke_races_creation(storage).await;
    passkey_credentials_cooldown_round_trip(storage).await;
    passkey_field_changes_compose(storage).await;
    passkey_writes_refuse_missing_credential(storage).await;
    passkey_credentials_bulk_delete_for_user(storage).await;
    passkey_registration_cooldown_round_trip(storage).await;
    passkey_registration_delete_for_user(storage).await;
    passkey_authentication_single_use(storage).await;
    single_use_under_concurrency(storage).await;
    passkey_challenge_purge_expired(storage).await;
    owner_indexes_track_removals(storage).await;
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
        last_used_at: now - Duration::hours(2),
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
    assert_refused(
        users.create_user(user(id, "different@example.com")).await,
        StorageErrorKind::Conflict,
        "duplicate id should error",
    );
    // Duplicate email is rejected.
    assert_refused(
        users
            .create_user(user(UserId::new(), "round-trip@example.com"))
            .await,
        StorageErrorKind::Conflict,
        "duplicate email should error",
    );

    // Marking the email verified is observable.
    users
        .mark_email_verified(id, ts(2026, 2, 1))
        .await
        .expect("mark verified");
    let verified = User {
        email_verified_at: Some(ts(2026, 2, 1)),
        updated_at: ts(2026, 2, 1),
        ..record
    };
    assert_eq!(
        users.find_user_by_id(id).await.expect("find updated"),
        Some(verified.clone()),
    );

    // Account status round-trips: flipping to `Disabled { at }` and back must
    // survive a write/read cycle, variant and timestamp intact. This is what
    // proves every adapter actually persists the new state.
    let disabled_at = ts(2026, 2, 15);
    users
        .set_user_status(id, AccountStatus::Disabled { at: disabled_at }, disabled_at)
        .await
        .expect("disable");
    let disabled = User {
        status: AccountStatus::Disabled { at: disabled_at },
        updated_at: disabled_at,
        ..verified
    };
    let reread = users
        .find_user_by_id(id)
        .await
        .expect("find disabled")
        .expect("disabled user present");
    assert_eq!(reread, disabled, "disabled status round-trips");
    assert!(!reread.status.is_active(), "disabled account is not active");

    // And back to active.
    users
        .set_user_status(id, AccountStatus::Active, ts(2026, 2, 20))
        .await
        .expect("reactivate");
    let reread = users
        .find_user_by_id(id)
        .await
        .expect("find reactivated")
        .expect("reactivated user present");
    assert_eq!(
        reread,
        User {
            status: AccountStatus::Active,
            updated_at: ts(2026, 2, 20),
            ..disabled
        },
        "reactivation clears the disabled timestamp",
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

/// `set_user_email` moves the address: the new one resolves to the user, the
/// old one is released for reuse, and an address another user holds is
/// refused without changing either user.
async fn users_email_change(storage: &Storage) {
    let users = &storage.users;
    let id = UserId::new();
    users
        .create_user(user(id, "before-change@example.com"))
        .await
        .expect("create");
    let other = UserId::new();
    users
        .create_user(user(other, "taken@example.com"))
        .await
        .expect("create other");

    let at = ts(2026, 3, 1);
    users
        .set_user_email(id, "after-change@example.com", at)
        .await
        .expect("change email");
    let changed = users
        .find_user_by_email("after-change@example.com")
        .await
        .expect("find new address")
        .expect("new address resolves");
    assert_eq!(changed.id, id);
    assert_eq!(changed.email.as_deref(), Some("after-change@example.com"));
    assert_eq!(changed.email_verified_at, Some(at));
    assert_eq!(changed.updated_at, at);
    assert!(
        users
            .find_user_by_email("before-change@example.com")
            .await
            .expect("find old address")
            .is_none(),
        "old address no longer resolves",
    );
    users
        .create_user(user(UserId::new(), "before-change@example.com"))
        .await
        .expect("old address is free for reuse");

    assert_refused(
        users
            .set_user_email(id, "taken@example.com", ts(2026, 3, 2))
            .await,
        StorageErrorKind::Conflict,
        "an address another user holds is refused",
    );
    assert_eq!(
        users
            .find_user_by_id(id)
            .await
            .expect("find after refusal")
            .expect("user present"),
        changed,
        "a refused change leaves the user untouched",
    );
    assert_eq!(
        users
            .find_user_by_email("taken@example.com")
            .await
            .expect("find taken address")
            .map(|u| u.id),
        Some(other),
        "a refused change leaves the holder untouched",
    );

    // Setting the address the user already has is allowed.
    users
        .set_user_email(id, "after-change@example.com", ts(2026, 3, 3))
        .await
        .expect("re-set own address");
}

/// Field-level changes never overwrite each other: a status change and an
/// email change to the same user both survive, in either order. Each setter is
/// a single atomic write that touches only its own fields, so any concurrent
/// interleaving of the two is equivalent to one of these orders.
async fn users_field_changes_compose(storage: &Storage) {
    let users = &storage.users;
    let disabled = AccountStatus::Disabled { at: ts(2026, 4, 1) };

    let status_first = UserId::new();
    users
        .create_user(user(status_first, "status-first@example.com"))
        .await
        .expect("create");
    users
        .set_user_status(status_first, disabled.clone(), ts(2026, 4, 1))
        .await
        .expect("disable");
    users
        .set_user_email(status_first, "status-first-new@example.com", ts(2026, 4, 2))
        .await
        .expect("change email");
    let reread = users
        .find_user_by_id(status_first)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(reread.status, disabled, "email change kept the disable");
    assert_eq!(
        reread.email.as_deref(),
        Some("status-first-new@example.com")
    );

    let email_first = UserId::new();
    users
        .create_user(user(email_first, "email-first@example.com"))
        .await
        .expect("create");
    users
        .set_user_email(email_first, "email-first-new@example.com", ts(2026, 4, 1))
        .await
        .expect("change email");
    users
        .set_user_status(email_first, disabled.clone(), ts(2026, 4, 2))
        .await
        .expect("disable");
    let reread = users
        .find_user_by_id(email_first)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(reread.status, disabled);
    assert_eq!(
        reread.email.as_deref(),
        Some("email-first-new@example.com"),
        "disable kept the email change",
    );
    assert_eq!(reread.email_verified_at, Some(ts(2026, 4, 1)));
}

/// Every field-level setter refuses a user that does not exist rather than
/// creating one.
async fn users_setters_refuse_missing_user(storage: &Storage) {
    let users = &storage.users;
    let missing = UserId::new();
    assert_refused(
        users
            .set_user_status(missing, AccountStatus::Active, ts(2026, 5, 1))
            .await,
        StorageErrorKind::NotFound,
        "status of a missing user",
    );
    assert_refused(
        users
            .set_user_email(missing, "ghost@example.com", ts(2026, 5, 1))
            .await,
        StorageErrorKind::NotFound,
        "email of a missing user",
    );
    assert_refused(
        users.mark_email_verified(missing, ts(2026, 5, 1)).await,
        StorageErrorKind::NotFound,
        "verify a missing user",
    );
    assert!(
        users
            .find_user_by_id(missing)
            .await
            .expect("find missing")
            .is_none(),
        "no setter creates the user",
    );
    assert!(
        users
            .find_user_by_email("ghost@example.com")
            .await
            .expect("find ghost address")
            .is_none(),
        "a refused email change claims no address",
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
        last_used_at: now,
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

    // delete_sessions_for_user with an exception keeps it, removes the rest.
    let removed = sessions
        .delete_sessions_for_user(user_id, Some(keep.id))
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

    // delete_sessions_for_user without one clears the rest for this user.
    let removed = sessions
        .delete_sessions_for_user(user_id, None)
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
        last_used_at: now - Duration::hours(2),
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
        last_used_at: now,
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

/// `SessionStore::touch_session` persists the slid `last_used_at` and
/// `expires_at` for a present session — visible through both resolution paths —
/// while leaving every other field unchanged.
async fn session_touch_slides_deadline(storage: &Storage) {
    let created_at = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "touch-slide@example.com"))
        .await
        .expect("user");

    let sessions = &storage.sessions;
    let token_hash = hash_token("touch-slide");
    let original = Session {
        id: SessionId::new(),
        user_id,
        token_hash,
        created_at,
        last_used_at: created_at,
        // Future-dated so the row is never evicted out from under the read
        // assertions on TTL-bearing backends.
        expires_at: ts(2099, 1, 1),
        ip: Some("203.0.113.9".into()),
        user_agent: Some("touch-agent".into()),
        recovery_cooldown_until: Some(ts(2099, 6, 1)),
    };
    sessions
        .create_session(original.clone())
        .await
        .expect("create session");

    let new_last_used_at = ts(2026, 2, 1);
    let new_expires_at = ts(2099, 3, 1);
    sessions
        .touch_session(original.id, new_last_used_at, new_expires_at)
        .await
        .expect("touch session");

    // Both resolution paths reflect the slid timestamps.
    let by_id = sessions
        .find_session_by_id(original.id)
        .await
        .expect("find by id")
        .expect("session present after touch");
    assert_eq!(by_id.last_used_at, new_last_used_at, "last_used_at slid");
    assert_eq!(by_id.expires_at, new_expires_at, "expires_at slid");

    let by_hash = sessions
        .find_session_by_token_hash(&token_hash)
        .await
        .expect("find by hash")
        .expect("session present after touch by hash");
    assert_eq!(by_hash.last_used_at, new_last_used_at);
    assert_eq!(by_hash.expires_at, new_expires_at);

    // Every other field is untouched.
    assert_eq!(by_id.id, original.id);
    assert_eq!(by_id.token_hash, original.token_hash);
    assert_eq!(by_id.created_at, original.created_at);
    assert_eq!(by_id.ip, original.ip);
    assert_eq!(by_id.user_agent, original.user_agent);
    assert_eq!(
        by_id.recovery_cooldown_until,
        original.recovery_cooldown_until,
    );

    sessions
        .delete_session(original.id)
        .await
        .expect("cleanup session");
}

/// Anti-resurrection: touching a session id that does not exist (deleted, or
/// never created) returns `Ok` and MUST NOT create a row. This is the security
/// contract that stops a touch racing a revoke from bringing a session back.
async fn session_touch_does_not_resurrect(storage: &Storage) {
    let created_at = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "touch-resurrect@example.com"))
        .await
        .expect("user");

    let sessions = &storage.sessions;

    // Case 1: an id that was never created.
    let phantom = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("touch-never-created"),
        created_at,
        last_used_at: created_at,
        expires_at: ts(2099, 1, 1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    sessions
        .touch_session(phantom.id, created_at, ts(2099, 2, 1))
        .await
        .expect("touch of never-created id is Ok");
    assert!(
        sessions
            .find_session_by_id(phantom.id)
            .await
            .expect("find never-created")
            .is_none(),
        "touching a never-created id must not create a row",
    );

    // Case 2: an id created then deleted, touched afterwards.
    let revoked = Session {
        token_hash: hash_token("touch-after-delete"),
        ..phantom.clone()
    };
    let revoked = Session {
        id: SessionId::new(),
        ..revoked
    };
    sessions
        .create_session(revoked.clone())
        .await
        .expect("create revoked");
    sessions
        .delete_session(revoked.id)
        .await
        .expect("delete revoked");
    sessions
        .touch_session(revoked.id, created_at, ts(2099, 2, 1))
        .await
        .expect("touch of deleted id is Ok");
    assert!(
        sessions
            .find_session_by_id(revoked.id)
            .await
            .expect("find deleted")
            .is_none(),
        "touching a deleted id must not resurrect the session",
    );
    assert!(
        sessions
            .find_session_by_token_hash(&revoked.token_hash)
            .await
            .expect("find deleted by hash")
            .is_none(),
        "the resurrected row must not be reachable by token hash either",
    );
}

/// Rounds of [`session_revoke_races_creation`]: each round races one bulk
/// revoke against [`RACERS`] session creations.
const REVOKE_ROUNDS: usize = 8;

/// A bulk revoke racing session creation never half-removes a session. Every
/// session that survives the revoke is still listed for its user and is
/// removed by the next revoke. Odd rounds revoke with an exception, which must
/// survive its round. An adapter that drops its whole per-user index
/// after enumerating it would orphan a session created in between: the
/// session still resolves, but no listing or later revoke can reach it.
async fn session_revoke_races_creation(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "revoke-race@example.com"))
        .await
        .expect("user");

    let session = |token: String| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(&token),
        created_at: now,
        last_used_at: now,
        expires_at: ts(2099, 1, 1),
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    let create = |session: Session| {
        let sessions = storage.sessions.clone();
        tokio::spawn(async move {
            sessions
                .create_session(session)
                .await
                .expect("create session");
        })
    };

    let mut created = Vec::new();
    for round in 0..REVOKE_ROUNDS {
        let kept = session(format!("revoke-race-{round}-kept"));
        storage
            .sessions
            .create_session(kept.clone())
            .await
            .expect("create kept session");
        let except = (round % 2 == 1).then_some(kept.id);

        let batch: Vec<Session> = (0..RACERS)
            .map(|i| session(format!("revoke-race-{round}-{i}")))
            .collect();
        let (before, after) = batch.split_at(RACERS / 2);
        let mut tasks: Vec<_> = before.iter().cloned().map(create).collect();
        let sessions = storage.sessions.clone();
        tasks.push(tokio::spawn(async move {
            sessions
                .delete_sessions_for_user(user_id, except)
                .await
                .expect("revoke");
        }));
        tasks.extend(after.iter().cloned().map(create));
        for task in tasks {
            task.await.expect("race task");
        }

        let kept_resolves = storage
            .sessions
            .find_session_by_token_hash(&kept.token_hash)
            .await
            .expect("find kept session")
            .is_some();
        assert_eq!(
            kept_resolves,
            except.is_some(),
            "a revoke deletes the pre-existing session unless it is the exception",
        );
        created.push(kept);
        created.extend(batch);
    }

    let listed: std::collections::HashSet<_> = storage
        .sessions
        .list_for_user(user_id, now)
        .await
        .expect("list")
        .iter()
        .map(|s| s.id)
        .collect();
    for s in &created {
        let resolves = storage
            .sessions
            .find_session_by_token_hash(&s.token_hash)
            .await
            .expect("find by hash")
            .is_some();
        assert!(
            !resolves || listed.contains(&s.id),
            "a session that survived a racing revoke is still listed",
        );
    }

    let removed = storage
        .sessions
        .delete_sessions_for_user(user_id, None)
        .await
        .expect("second revoke");
    assert_eq!(
        removed,
        listed.len() as u64,
        "the second revoke removes every survivor",
    );
    for s in &created {
        assert!(
            storage
                .sessions
                .find_session_by_token_hash(&s.token_hash)
                .await
                .expect("find by hash after second revoke")
                .is_none(),
            "no session resolves after the second revoke",
        );
    }
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

    // A recorded use writes the blob, the backup flags and the last-used time;
    // a rename writes only the name. Every other field keeps the value it was
    // registered with.
    let updated_blob = b"opaque-serialised-passkey-blob-v2".to_vec();
    let used_at = now + Duration::minutes(5);
    credentials
        .record_passkey_use(
            &credential_id,
            PasskeyUse {
                passkey: updated_blob.clone(),
                // The credential became backed up after registration.
                backup_eligible: true,
                backup_state: true,
                used_at,
            },
        )
        .await
        .expect("record use");
    credentials
        .set_passkey_name(&credential_id, Some("renamed security key"))
        .await
        .expect("rename passkey");
    let updated = StoredPasskey {
        passkey: updated_blob.clone(),
        name: Some("renamed security key".into()),
        last_used_at: Some(used_at),
        backup_eligible: true,
        backup_state: true,
        ..by_id
    };

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
    assert_eq!(
        listed[0].transports,
        vec!["usb".to_string(), "nfc".to_string()],
        "transports preserved on update",
    );
    assert!(listed[0].backup_eligible, "backup flags refreshed on use");
    assert!(listed[0].backup_state);
    assert_eq!(
        listed[0].recovery_cooldown_until,
        Some(cooldown_until),
        "cool-down preserved on update",
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
    assert_eq!(
        summary.transports,
        vec!["usb".to_string(), "nfc".to_string()]
    );
    assert!(summary.backup_eligible);
    assert!(summary.backup_state);
    assert_eq!(summary.recovery_cooldown_until, Some(cooldown_until));
    // The same record viewed as a summary is byte-for-byte the projection.
    assert_eq!(*summary, PasskeySummary::from(listed[0].clone()));

    // A second `add_passkey` with the same credential id must be rejected,
    // even when it claims a different owner and carries a different blob.
    // This is what stops one user from registering another user's credential
    // id; the lookup must keep resolving to the original owner.
    let other_user_id = UserId::new();
    storage
        .users
        .create_user(user(other_user_id, "passkey-hijack@example.com"))
        .await
        .expect("other user");
    let hijack = StoredPasskey {
        credential_id: credential_id.clone(),
        user_id: other_user_id,
        passkey: b"hijacker-blob".to_vec(),
        name: Some("hijacker key".into()),
        created_at: now,
        last_used_at: None,
        aaguid: None,
        transports: vec![],
        backup_eligible: false,
        backup_state: false,
        recovery_cooldown_until: None,
    };
    assert_refused(
        credentials.add_passkey(hijack).await,
        StorageErrorKind::Conflict,
        "duplicate credential id should error",
    );

    let still_owned = credentials
        .find_passkey_by_credential_id(&credential_id)
        .await
        .expect("find by credential id after duplicate attempt")
        .expect("passkey still present");
    assert_eq!(
        still_owned.user_id, user_id,
        "the original owner is preserved after a duplicate-id attempt",
    );
}

/// A credential with the given id, owned by `user_id`, registered at
/// `created_at` with no name, no use and no backup.
fn passkey(user_id: UserId, credential_id: &[u8], created_at: DateTime<Utc>) -> StoredPasskey {
    StoredPasskey {
        credential_id: credential_id.to_vec(),
        user_id,
        passkey: b"opaque-serialised-passkey-blob".to_vec(),
        name: None,
        created_at,
        last_used_at: None,
        aaguid: None,
        transports: vec!["usb".into()],
        backup_eligible: false,
        backup_state: false,
        recovery_cooldown_until: None,
    }
}

/// Field-level credential writes never overwrite each other: a recorded use
/// and a rename of the same credential both survive, in either order, and
/// neither moves the owner or the registration time. Each write is a single
/// atomic change to its own fields, so any concurrent interleaving of the two
/// (a sign-in and a rename racing from the same read of the row) is
/// equivalent to one of these orders.
async fn passkey_field_changes_compose(storage: &Storage) {
    let created_at = ts(2026, 6, 1);
    let used_at = ts(2026, 6, 2);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "passkey-compose@example.com"))
        .await
        .expect("user");
    let credentials = &storage.passkey_credentials;
    let used = || PasskeyUse {
        passkey: b"opaque-serialised-passkey-blob-advanced".to_vec(),
        backup_eligible: true,
        backup_state: true,
        used_at,
    };

    for (credential_id, use_first) in [
        (&b"compose-use-first"[..], true),
        (&b"compose-rename-first"[..], false),
    ] {
        credentials
            .add_passkey(passkey(user_id, credential_id, created_at))
            .await
            .expect("add passkey");
        if use_first {
            credentials
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }
        credentials
            .set_passkey_name(credential_id, Some("laptop"))
            .await
            .expect("rename");
        if !use_first {
            credentials
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }

        let reread = credentials
            .find_passkey_by_credential_id(credential_id)
            .await
            .expect("find")
            .expect("present");
        assert_eq!(
            reread.passkey,
            used().passkey,
            "the rename kept the recorded blob (use first: {use_first})",
        );
        assert_eq!(reread.last_used_at, Some(used_at));
        assert!(reread.backup_eligible && reread.backup_state);
        assert_eq!(
            reread.name.as_deref(),
            Some("laptop"),
            "the recorded use kept the rename (use first: {use_first})",
        );
        assert_eq!(reread.user_id, user_id, "the owner never moves");
        assert_eq!(reread.created_at, created_at, "registration time is fixed");
    }

    // Clearing the name removes it and leaves the recorded use in place.
    credentials
        .set_passkey_name(b"compose-use-first", None)
        .await
        .expect("clear name");
    let cleared = credentials
        .find_passkey_by_credential_id(b"compose-use-first")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(cleared.name, None, "a cleared name reads back as none");
    assert_eq!(cleared.last_used_at, Some(used_at));
}

/// Every field-level credential write refuses a credential that does not
/// exist rather than creating one.
async fn passkey_writes_refuse_missing_credential(storage: &Storage) {
    let credentials = &storage.passkey_credentials;
    let missing = b"conformance-missing-credential";
    assert_refused(
        credentials
            .record_passkey_use(
                missing,
                PasskeyUse {
                    passkey: b"ghost-blob".to_vec(),
                    backup_eligible: false,
                    backup_state: false,
                    used_at: ts(2026, 6, 1),
                },
            )
            .await,
        StorageErrorKind::NotFound,
        "use of a missing credential",
    );
    assert_refused(
        credentials.set_passkey_name(missing, Some("ghost")).await,
        StorageErrorKind::NotFound,
        "rename of a missing credential",
    );
    assert!(
        credentials
            .find_passkey_by_credential_id(missing)
            .await
            .expect("find missing")
            .is_none(),
        "no write creates the credential",
    );
}

/// `PasskeyCredentialStore::delete_passkeys_for_user` removes every credential
/// belonging to the target user in one set-based operation, returns the number
/// removed, and leaves another user's credential untouched. This backs account
/// deletion's credential cascade. `count_passkeys_for_user` is checked along
/// the way: it is owner-scoped and tracks single and bulk removals.
async fn passkey_credentials_bulk_delete_for_user(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let target = UserId::new();
    let bystander = UserId::new();
    storage
        .users
        .create_user(user(target, "bulk-delete-creds-target@example.com"))
        .await
        .expect("target user");
    storage
        .users
        .create_user(user(bystander, "bulk-delete-creds-bystander@example.com"))
        .await
        .expect("bystander user");

    let credentials = &storage.passkey_credentials;
    let add = |user_id: UserId, credential_id: Vec<u8>| {
        let credential = StoredPasskey {
            credential_id,
            user_id,
            passkey: b"opaque-serialised-passkey-blob".to_vec(),
            name: Some("security key".into()),
            created_at: now,
            last_used_at: None,
            aaguid: None,
            transports: vec!["usb".into()],
            backup_eligible: false,
            backup_state: false,
            recovery_cooldown_until: None,
        };
        async move {
            credentials
                .add_passkey(credential)
                .await
                .expect("add passkey");
        }
    };

    add(target, b"bulk-delete-target-cred-1".to_vec()).await;
    add(target, b"bulk-delete-target-cred-2".to_vec()).await;
    add(target, b"bulk-delete-target-cred-3".to_vec()).await;
    let bystander_cred = b"bulk-delete-bystander-cred".to_vec();
    add(bystander, bystander_cred.clone()).await;

    // The count is scoped to the owner and tracks a single removal.
    let count = |user_id: UserId| async move {
        credentials
            .count_passkeys_for_user(user_id)
            .await
            .expect("count passkeys")
    };
    assert_eq!(
        count(target).await,
        3,
        "count covers the owner's credentials"
    );
    assert_eq!(count(bystander).await, 1, "count excludes other users");
    credentials
        .delete_passkey(b"bulk-delete-target-cred-3")
        .await
        .expect("delete one passkey");
    assert_eq!(count(target).await, 2, "count drops after a single removal");

    let removed = credentials
        .delete_passkeys_for_user(target)
        .await
        .expect("delete passkeys for user");
    assert_eq!(
        removed, 2,
        "the return count equals the target user's credential count",
    );
    assert_eq!(
        count(target).await,
        0,
        "count is zero after the bulk delete"
    );
    assert_eq!(
        count(bystander).await,
        1,
        "another user's count is untouched"
    );

    assert!(
        credentials
            .list_passkeys_for_user(target)
            .await
            .expect("list target after delete")
            .is_empty(),
        "all of the target user's credentials are removed",
    );

    // The bystander's credential is untouched.
    let surviving = credentials
        .list_passkeys_for_user(bystander)
        .await
        .expect("list bystander after delete");
    assert_eq!(surviving.len(), 1, "another user's credential survives");
    assert_eq!(surviving[0].credential_id, bystander_cred);
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

/// An authentication ceremony round-trips its purpose and opaque state
/// through `put`/`take` and is single-use: `take_authentication` removes the
/// challenge before returning it, so a second take observes nothing. Both
/// purposes share the one table, so each must come back as it was stored —
/// core relies on the purpose to keep login and re-authentication apart.
/// Authentications are not user-scoped, so unlike registrations they carry no
/// secondary index.
async fn passkey_authentication_single_use(storage: &Storage) {
    let now = ts(2026, 1, 1);
    for purpose in [AuthenticationPurpose::Login, AuthenticationPurpose::Reauth] {
        let challenge_id = PasskeyChallengeId::new();
        let state_blob = b"opaque-serialised-authentication-state".to_vec();
        storage
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

        let taken = storage
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
            storage
                .passkey_challenges
                .take_authentication(challenge_id)
                .await
                .expect("second take")
                .is_none(),
            "authentication challenges are single-use",
        );
    }
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
            purpose: AuthenticationPurpose::Login,
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

/// Spawn [`RACERS`] copies of `redeem` as concurrent tasks and return how many
/// of them observed the row.
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

/// Single-use holds under concurrency: when many callers race to consume one
/// verification token, or to take one registration or authentication
/// ceremony, exactly one observes it. A look-up followed by a separate delete
/// would let two requests carrying the same secret both succeed; the stores
/// must remove and return the row in one atomic step.
async fn single_use_under_concurrency(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "race@example.com"))
        .await
        .expect("user");

    let hash = hash_token("race-consume-token");
    storage
        .verification_tokens
        .create_token(VerificationToken {
            token_hash: hash,
            user_id,
            purpose: VerificationPurpose::Signup,
            new_email: None,
            created_at: now,
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("create token");
    let consumed = count_redeemers(|| {
        let tokens = storage.verification_tokens.clone();
        async move {
            tokens
                .consume_token(&hash, VerificationPurpose::Signup)
                .await
                .expect("consume")
                .is_some()
        }
    })
    .await;
    assert_eq!(consumed, 1, "exactly one caller consumes the token");

    let registration = PasskeyChallengeId::new();
    storage
        .passkey_challenges
        .put_registration(StoredPasskeyRegistration {
            id: registration,
            user_id,
            state: b"race-registration".to_vec(),
            created_at: now,
            expires_at: ts(2099, 1, 1),
            recovery_cooldown_until: None,
        })
        .await
        .expect("put registration");
    let taken = count_redeemers(|| {
        let challenges = storage.passkey_challenges.clone();
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
    storage
        .passkey_challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: authentication,
            purpose: AuthenticationPurpose::Login,
            state: b"race-authentication".to_vec(),
            created_at: now,
            expires_at: ts(2099, 1, 1),
        })
        .await
        .expect("put authentication");
    let taken = count_redeemers(|| {
        let challenges = storage.passkey_challenges.clone();
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

/// Removing one row also drops it from its owner's index. After a consume,
/// take, single delete, or purge, the per-user count and the bulk deletes see
/// only the rows that remain. An adapter that maintains its own per-user index
/// must unlink the entry together with the row; a stale entry inflates
/// `count_registrations_for_user` toward the outstanding-ceremony cap.
async fn owner_indexes_track_removals(storage: &Storage) {
    let now = ts(2026, 1, 1);
    let user_id = UserId::new();
    storage
        .users
        .create_user(user(user_id, "index-removals@example.com"))
        .await
        .expect("user");

    // Sessions: one deleted by id, one purged, one kept, one left over.
    let sessions = &storage.sessions;
    let session = |token: &str, expires_at| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(token),
        created_at: ts(2020, 1, 1),
        last_used_at: ts(2020, 1, 1),
        expires_at,
        ip: None,
        user_agent: None,
        recovery_cooldown_until: None,
    };
    let deleted = session("index-deleted-session", ts(2099, 1, 1));
    let expired = session("index-expired-session", ts(2020, 1, 2));
    let kept = session("index-kept-session", ts(2099, 1, 1));
    let other = session("index-other-session", ts(2099, 1, 1));
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

    // Verification tokens: one consumed, one purged, one left over.
    let tokens = &storage.verification_tokens;
    let token = |raw: &str, expires_at| VerificationToken {
        token_hash: hash_token(raw),
        user_id,
        purpose: VerificationPurpose::Recovery,
        new_email: None,
        created_at: ts(2020, 1, 1),
        expires_at,
    };
    let consumed = token("index-consumed-token", ts(2099, 1, 1));
    let expired = token("index-expired-token", ts(2020, 1, 2));
    let remaining = token("index-remaining-token", ts(2099, 1, 1));
    for t in [&consumed, &expired, &remaining] {
        tokens.create_token(t.clone()).await.expect("create token");
    }
    assert!(
        tokens
            .consume_token(&consumed.token_hash, VerificationPurpose::Recovery)
            .await
            .expect("consume token")
            .is_some(),
        "the token is consumed",
    );
    assert!(
        tokens.purge_expired(now).await.expect("purge tokens") >= 1,
        "the expired token was purged",
    );
    assert_eq!(
        tokens
            .delete_tokens_for_user(user_id, VerificationPurpose::Recovery)
            .await
            .expect("delete tokens"),
        1,
        "only the remaining token is left to remove",
    );

    // Registrations: one taken, one purged, one left over. The count is the
    // index read the outstanding-ceremony cap relies on.
    let challenges = &storage.passkey_challenges;
    let registration = |expires_at| StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        user_id,
        state: b"index-registration".to_vec(),
        created_at: ts(2020, 1, 1),
        expires_at,
        recovery_cooldown_until: None,
    };
    let taken = registration(ts(2099, 1, 1));
    let expired = registration(ts(2020, 1, 2));
    let remaining = registration(ts(2099, 1, 1));
    for r in [&taken, &expired, &remaining] {
        challenges
            .put_registration(r.clone())
            .await
            .expect("put registration");
    }
    let count = || async {
        challenges
            .count_registrations_for_user(user_id)
            .await
            .expect("count registrations")
    };
    assert_eq!(count().await, 3, "all three registrations are counted");
    assert!(
        challenges
            .take_registration(taken.id)
            .await
            .expect("take registration")
            .is_some(),
        "the registration is taken",
    );
    assert_eq!(
        count().await,
        2,
        "a taken registration is no longer counted"
    );
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
        "a purged registration is no longer counted"
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
