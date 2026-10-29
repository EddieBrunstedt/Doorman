use doorman_core::error::StorageErrorKind;
use doorman_core::storage::{RecordStores, User, UserId, UserStatus};

use crate::fixtures::{assert_refused, days, user};

pub(crate) async fn users_round_trip(stores: &RecordStores) {
    let users = &stores.users;
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

    assert_refused(
        users.create_user(user(id, "different@example.com")).await,
        StorageErrorKind::Conflict,
        "duplicate id should error",
    );
    assert_refused(
        users
            .create_user(user(UserId::new(), "round-trip@example.com"))
            .await,
        StorageErrorKind::Conflict,
        "duplicate email should error",
    );

    users
        .mark_signed_up(id, days(31))
        .await
        .expect("mark signed up");
    let signed_up = User {
        signed_up_at: Some(days(31)),
        updated_at: days(31),
        ..record
    };
    assert_eq!(
        users.find_user_by_id(id).await.expect("find updated"),
        Some(signed_up.clone()),
    );

    let disabled_at = days(45);
    users
        .set_user_status(id, UserStatus::Disabled { at: disabled_at }, disabled_at)
        .await
        .expect("disable");
    let disabled = User {
        status: UserStatus::Disabled { at: disabled_at },
        updated_at: disabled_at,
        ..signed_up
    };
    let reread = users
        .find_user_by_id(id)
        .await
        .expect("find disabled")
        .expect("disabled user present");
    assert_eq!(reread, disabled, "disabled status round-trips");
    assert!(!reread.status.is_active(), "disabled user is not active");

    users
        .set_user_status(id, UserStatus::Active, days(50))
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
            status: UserStatus::Active,
            updated_at: days(50),
            ..disabled
        },
        "reactivation clears the disabled timestamp",
    );

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

pub(crate) async fn users_email_change(stores: &RecordStores) {
    let users = &stores.users;
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
    users
        .mark_signed_up(id, days(58))
        .await
        .expect("mark signed up");

    let at = days(59);
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
    assert_eq!(
        changed.signed_up_at,
        Some(days(58)),
        "an email change keeps signup finished",
    );
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
            .set_user_email(id, "taken@example.com", days(60))
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

    users
        .set_user_email(id, "after-change@example.com", days(61))
        .await
        .expect("re-set own address");
}

// Core alone decides which addresses are the same; a backend that folds accents
// or case would merge users core keeps apart.
pub(crate) async fn users_email_matches_exactly(stores: &RecordStores) {
    let users = &stores.users;
    for (stored, other) in [
        ("jos\u{e9}@example.com", "jose@example.com"),
        ("ren\u{e9}@example.com", "ren\u{c9}@example.com"),
        ("stra\u{df}e@example.com", "strasse@example.com"),
    ] {
        let first = user(UserId::new(), stored);
        users.create_user(first.clone()).await.expect("create");
        assert!(
            users
                .find_user_by_email(other)
                .await
                .expect("find other")
                .is_none(),
            "{other} matched {stored}",
        );
        let second = user(UserId::new(), other);
        users
            .create_user(second.clone())
            .await
            .unwrap_or_else(|e| panic!("{other} refused beside {stored}: {e}"));
        assert_eq!(
            users.find_user_by_email(other).await.expect("find other"),
            Some(second),
        );
        assert_eq!(
            users.find_user_by_email(stored).await.expect("find stored"),
            Some(first),
        );
    }
}

pub(crate) async fn users_field_changes_compose(stores: &RecordStores) {
    let users = &stores.users;
    let disabled = UserStatus::Disabled { at: days(90) };

    let status_first = UserId::new();
    users
        .create_user(user(status_first, "status-first@example.com"))
        .await
        .expect("create");
    users
        .set_user_status(status_first, disabled.clone(), days(90))
        .await
        .expect("disable");
    users
        .set_user_email(status_first, "status-first-new@example.com", days(91))
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
        .set_user_email(email_first, "email-first-new@example.com", days(90))
        .await
        .expect("change email");
    users
        .set_user_status(email_first, disabled.clone(), days(91))
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
}

pub(crate) async fn users_setters_refuse_missing_user(stores: &RecordStores) {
    let users = &stores.users;
    let missing = UserId::new();
    assert_refused(
        users
            .set_user_status(missing, UserStatus::Active, days(120))
            .await,
        StorageErrorKind::NotFound,
        "status of a missing user",
    );
    assert_refused(
        users
            .set_user_email(missing, "ghost@example.com", days(120))
            .await,
        StorageErrorKind::NotFound,
        "email of a missing user",
    );
    assert_refused(
        users.mark_signed_up(missing, days(120)).await,
        StorageErrorKind::NotFound,
        "mark a missing user signed up",
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
