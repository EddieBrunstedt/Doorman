use std::future::Future;

use chrono::{DateTime, Duration, TimeZone, Utc};
use doorman_core::email::MAX_EMAIL_ADDRESS_LEN;
use doorman_core::error::{StorageErrorKind, StorageResult};
use doorman_core::passkey::{MAX_CREDENTIAL_ID_LEN, MAX_PASSKEY_NAME_LEN};
use doorman_core::session::{SessionContext, hash_token};
use doorman_core::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, ExpiringStores, PasskeyChallengeId,
    PasskeyUse, RecordStores, RegistrationPurpose, Session, SessionId, SessionTransport, Storage,
    StoredPasskey, StoredPasskeyAuthentication, StoredPasskeyRegistration, User, UserId,
    UserStatus,
};

// After any real date a run happens on: a backend that expires rows by its own
// clock must not drop a fixture before the check reaches it.
fn present() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

fn days(n: i64) -> DateTime<Utc> {
    present() + Duration::days(n)
}

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
        signed_up_at: None,
        status: UserStatus::Active,
        created_at: present(),
        updated_at: present(),
    }
}

const RACERS: usize = 64;

// One worker would run each racer to completion before the next, so a store
// whose operations never await could never be raced.
const MIN_WORKERS: usize = 2;

pub async fn run(storage: &Storage) {
    let mut checks = Checks::start();
    record_checks(&mut checks, &storage.records).await;
    expiring_checks(&mut checks, &storage.expiring).await;
    checks.finish();
}

pub async fn run_records(stores: &RecordStores) {
    let mut checks = Checks::start();
    record_checks(&mut checks, stores).await;
    checks.finish();
}

pub async fn run_expiring(stores: &ExpiringStores) {
    let mut checks = Checks::start();
    expiring_checks(&mut checks, stores).await;
    checks.finish();
}

struct Checks {
    run: usize,
    failed: Vec<String>,
}

impl Checks {
    fn start() -> Self {
        let workers = tokio::runtime::Handle::current().metrics().num_workers();
        assert!(
            workers >= MIN_WORKERS,
            "the conformance suite races concurrent callers and needs at least \
             {MIN_WORKERS} runtime workers, got {workers}; run it under \
             #[tokio::test(flavor = \"multi_thread\", worker_threads = 4)]",
        );
        Self {
            run: 0,
            failed: Vec::new(),
        }
    }

    async fn run(&mut self, name: &str, check: impl Future<Output = ()> + Send + 'static) {
        self.run += 1;
        if let Err(err) = tokio::spawn(check).await {
            let message = if err.is_panic() {
                let payload = err.into_panic();
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panicked".to_string())
            } else {
                err.to_string()
            };
            self.failed
                .push(format!("- {name}: {}", message.replace('\n', "\n    ")));
        }
    }

    fn finish(self) {
        if !self.failed.is_empty() {
            panic!(
                "{} of {} conformance checks failed:\n{}",
                self.failed.len(),
                self.run,
                self.failed.join("\n"),
            );
        }
    }
}

// Runs each check in its own task, in order, so a failing check reports and
// the next one still runs.
macro_rules! checks {
    ($checks:expr, $stores:expr; $($check:ident),* $(,)?) => {
        $(
            let stores = $stores.clone();
            $checks
                .run(stringify!($check), async move { $check(&stores).await })
                .await;
        )*
    };
}

async fn record_checks(checks: &mut Checks, stores: &RecordStores) {
    checks!(checks, stores;
        users_round_trip,
        users_email_change,
        users_email_matches_exactly,
        records_hold_values_at_core_limits,
        users_field_changes_compose,
        users_setters_refuse_missing_user,
        passkeys_cool_down_round_trip,
        passkey_field_changes_compose,
        passkey_writes_refuse_missing_passkey,
        passkeys_bulk_delete_for_user,
    );
}

async fn expiring_checks(checks: &mut Checks, stores: &ExpiringStores) {
    checks!(checks, stores;
        email_link_single_use,
        email_link_email_change_payload,
        email_link_replaces_its_owners_link,
        email_link_racing_replaces_leave_one_link,
        email_link_replaces_racing_across_owners_keep_every_link,
        email_link_purge_and_delete,
        sessions_crud_and_queries,
        sessions_purge_expired,
        session_touch_slides_deadline,
        session_touch_does_not_resurrect,
        session_touch_races_revoke,
        session_revoke_races_creation,
        passkey_registration_round_trip,
        passkey_registration_delete_for_user,
        passkey_registration_delete_races_creation,
        passkey_authentication_single_use,
        single_use_under_concurrency,
        passkey_challenge_purge_expired,
        owner_indexes_track_removals,
        absent_lookups_return_none,
        inserts_refuse_duplicate_keys,
        expiring_hold_values_at_core_limits,
    );
}

async fn users_round_trip(stores: &RecordStores) {
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

async fn users_email_change(stores: &RecordStores) {
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
async fn users_email_matches_exactly(stores: &RecordStores) {
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

// Core bounds these values in bytes, while a backend may bound a column in characters, so each
// limit is filled once with one-byte characters (the most characters) and once with four-byte
// ones (the most bytes per character).
const FILLERS: [char; 2] = ['n', '\u{1f511}'];

fn at_limit(limit: usize, tag: &str, filler: char) -> String {
    let room = limit - tag.len();
    let value = format!(
        "{tag}{}{}",
        filler.to_string().repeat(room / filler.len_utf8()),
        "n".repeat(room % filler.len_utf8()),
    );
    assert_eq!(value.len(), limit);
    value
}

fn longest_email(tag: &str, filler: char) -> String {
    at_limit(MAX_EMAIL_ADDRESS_LEN - "@example.com".len(), tag, filler) + "@example.com"
}

async fn records_hold_values_at_core_limits(stores: &RecordStores) {
    for (i, filler) in FILLERS.into_iter().enumerate() {
        let owner = UserId::new();
        let email = longest_email(&format!("records-limit-{i}"), filler);
        let stored_user = user(owner, &email);
        stores
            .users
            .create_user(stored_user.clone())
            .await
            .expect("create the longest address");
        assert_eq!(
            stores
                .users
                .find_user_by_email(&email)
                .await
                .expect("find by email"),
            Some(stored_user),
        );

        let credential_id: Vec<u8> = (0..MAX_CREDENTIAL_ID_LEN).map(|b| (b + i) as u8).collect();
        let mut longest = passkey(owner, &credential_id, present());
        longest.name = Some(at_limit(MAX_PASSKEY_NAME_LEN, "name", filler));
        longest.transports = ["usb", "nfc", "ble", "internal", "hybrid", "test", "unknown"]
            .map(str::to_owned)
            .to_vec();
        stores
            .passkeys
            .add_passkey(longest.clone())
            .await
            .expect("add the longest passkey");
        let found = stores
            .passkeys
            .find_passkey_by_credential_id(&credential_id)
            .await
            .expect("find passkey")
            .expect("passkey present");
        assert_eq!(found.credential_id, longest.credential_id);
        assert_eq!(found.name, longest.name);
        assert_eq!(found.transports, longest.transports);
    }
}

async fn expiring_hold_values_at_core_limits(stores: &ExpiringStores) {
    for (i, filler) in FILLERS.into_iter().enumerate() {
        let user_id = UserId::new();
        let session = Session {
            id: SessionId::new(),
            user_id,
            token_hash: hash_token(&format!("session-at-limits-{i}")),
            transport: SessionTransport::Cookie,
            created_at: present(),
            last_used_at: present(),
            expires_at: days(1),
            ip: Some("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_string()),
            user_agent: Some(at_limit(
                SessionContext::MAX_USER_AGENT_LEN,
                "agent",
                filler,
            )),
            recovery_cool_down_until: None,
        };
        stores
            .sessions
            .create_session(session.clone())
            .await
            .expect("create the longest session");
        assert_eq!(
            stores
                .sessions
                .find_session_by_id(session.id)
                .await
                .expect("find session"),
            Some(session),
        );

        let email_change = EmailLink {
            token_hash: hash_token(&format!("link-at-limits-{i}")),
            user_id,
            purpose: EmailLinkPurpose::EmailChange,
            owner_email: Some(longest_email("link-owner", filler)),
            new_email: Some(longest_email("link-new", filler)),
            created_at: present(),
            expires_at: days(1),
        };
        stores
            .email_links
            .replace_link(email_change.clone())
            .await
            .expect("issue the longest link");
        assert_eq!(
            stores
                .email_links
                .redeem_link(&email_change.token_hash)
                .await
                .expect("redeem link"),
            Some(email_change),
        );

        let challenge_id = PasskeyChallengeId::new();
        let owner_email = Some(longest_email("registration-owner", filler));
        stores
            .passkey_challenges
            .put_registration(StoredPasskeyRegistration {
                id: challenge_id,
                purpose: RegistrationPurpose::Recovery,
                user_id,
                state: b"opaque-registration-state".to_vec(),
                owner_email: owner_email.clone(),
                created_at: present(),
                expires_at: days(1),
                recovery_cool_down_until: None,
            })
            .await
            .expect("put the longest registration");
        let taken = stores
            .passkey_challenges
            .take_registration(challenge_id)
            .await
            .expect("take registration")
            .expect("registration present");
        assert_eq!(taken.owner_email, owner_email);
    }
}

async fn users_field_changes_compose(stores: &RecordStores) {
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

async fn users_setters_refuse_missing_user(stores: &RecordStores) {
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

async fn email_link_single_use(stores: &ExpiringStores) {
    let user_id = UserId::new();

    let tokens = &stores.email_links;
    let hash = hash_token("single-use-token");
    tokens
        .replace_link(EmailLink {
            token_hash: hash,
            user_id,
            purpose: EmailLinkPurpose::Signup,
            owner_email: None,
            new_email: None,
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create");

    assert!(
        tokens
            .redeem_link(&hash)
            .await
            .expect("first redeem")
            .is_some(),
        "first redeem returns the token",
    );
    assert!(
        tokens
            .redeem_link(&hash)
            .await
            .expect("second redeem")
            .is_none(),
        "second redeem returns nothing",
    );

    let signup_hash = hash_token("purpose-carrying-token");
    tokens
        .replace_link(EmailLink {
            token_hash: signup_hash,
            user_id,
            purpose: EmailLinkPurpose::Signup,
            owner_email: None,
            new_email: None,
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create scoped");
    let redeemed = tokens
        .redeem_link(&signup_hash)
        .await
        .expect("redeem by hash")
        .expect("the link redeems by its hash alone");
    assert_eq!(
        redeemed.purpose,
        EmailLinkPurpose::Signup,
        "the link comes back with the purpose it was stored under",
    );
}

async fn email_link_email_change_payload(stores: &ExpiringStores) {
    let user_id = UserId::new();

    let tokens = &stores.email_links;
    let hash = hash_token("email-change-token");
    tokens
        .replace_link(EmailLink {
            token_hash: hash,
            user_id,
            purpose: EmailLinkPurpose::EmailChange,
            owner_email: Some("old-address@example.com".to_string()),
            new_email: Some("new-address@example.com".to_string()),
            created_at: present(),
            expires_at: days(365),
        })
        .await
        .expect("create email-change token");

    let redeemed = tokens
        .redeem_link(&hash)
        .await
        .expect("redeem")
        .expect("token present");
    assert_eq!(redeemed.purpose, EmailLinkPurpose::EmailChange);
    assert_eq!(
        redeemed.new_email.as_deref(),
        Some("new-address@example.com"),
        "the target address round-trips through storage",
    );
    assert_eq!(
        redeemed.owner_email.as_deref(),
        Some("old-address@example.com"),
        "the owner's address round-trips through storage",
    );
}

fn link(raw: &str, user_id: UserId, purpose: EmailLinkPurpose) -> EmailLink {
    EmailLink {
        token_hash: hash_token(raw),
        user_id,
        purpose,
        owner_email: Some(format!("{raw}@example.com")),
        new_email: None,
        created_at: present(),
        expires_at: days(365),
    }
}

async fn email_link_replaces_its_owners_link(stores: &ExpiringStores) {
    let owner = UserId::new();
    let bystander = UserId::new();

    let links = &stores.email_links;
    let first = link("replace-first", owner, EmailLinkPurpose::Signup);
    let other_purpose = link("replace-other-purpose", owner, EmailLinkPurpose::Recovery);
    let other_owner = link("replace-other-owner", bystander, EmailLinkPurpose::Signup);
    let second = link("replace-second", owner, EmailLinkPurpose::Signup);
    for l in [&first, &other_purpose, &other_owner, &second] {
        links.replace_link(l.clone()).await.expect("replace link");
    }

    assert!(
        links
            .redeem_link(&first.token_hash)
            .await
            .expect("redeem replaced")
            .is_none(),
        "a link replaced by its owner's next link of the same purpose no longer redeems",
    );
    assert_eq!(
        links
            .redeem_link(&second.token_hash)
            .await
            .expect("redeem replacement"),
        Some(second),
        "the replacing link redeems",
    );
    assert_eq!(
        links
            .redeem_link(&other_purpose.token_hash)
            .await
            .expect("redeem other purpose"),
        Some(other_purpose),
        "the owner's link of another purpose survives",
    );
    assert_eq!(
        links
            .redeem_link(&other_owner.token_hash)
            .await
            .expect("redeem other owner"),
        Some(other_owner),
        "another user's link of the same purpose survives",
    );
}

async fn email_link_racing_replaces_leave_one_link(stores: &ExpiringStores) {
    let owner = UserId::new();
    let raced: Vec<EmailLink> = (0..RACERS)
        .map(|i| {
            link(
                &format!("replace-race-{i}"),
                owner,
                EmailLinkPurpose::Signup,
            )
        })
        .collect();

    let tasks: Vec<_> = raced
        .iter()
        .cloned()
        .map(|l| {
            let links = stores.email_links.clone();
            tokio::spawn(async move { links.replace_link(l).await })
        })
        .collect();
    for task in tasks {
        task.await
            .expect("racer task")
            .expect("every racing replace is accepted");
    }

    let mut live = 0;
    for l in &raced {
        if stores
            .email_links
            .redeem_link(&l.token_hash)
            .await
            .expect("redeem raced link")
            .is_some()
        {
            live += 1;
        }
    }
    assert_eq!(
        live, 1,
        "racing replaces of one owner's link of one purpose leave exactly one link"
    );
}

async fn email_link_replaces_racing_across_owners_keep_every_link(stores: &ExpiringStores) {
    let raced: Vec<EmailLink> = (0..RACERS)
        .map(|i| {
            link(
                &format!("replace-across-owners-{i}"),
                UserId::new(),
                EmailLinkPurpose::Recovery,
            )
        })
        .collect();

    let tasks: Vec<_> = raced
        .iter()
        .cloned()
        .map(|l| {
            let links = stores.email_links.clone();
            tokio::spawn(async move { links.replace_link(l).await })
        })
        .collect();
    for task in tasks {
        task.await
            .expect("racer task")
            .expect("every racing replace is accepted");
    }

    for l in &raced {
        assert_eq!(
            stores
                .email_links
                .redeem_link(&l.token_hash)
                .await
                .expect("redeem raced link"),
            Some(l.clone()),
            "racing replaces by different users keep every user's link",
        );
    }
}

async fn email_link_purge_and_delete(stores: &ExpiringStores) {
    let user_id = UserId::new();
    let bystander = UserId::new();

    let tokens = &stores.email_links;
    let signup = link("delete-signup", user_id, EmailLinkPurpose::Signup);
    let recovery = link("delete-recovery", user_id, EmailLinkPurpose::Recovery);
    let survivor = link("delete-bystander", bystander, EmailLinkPurpose::Signup);
    for l in [&signup, &recovery, &survivor] {
        tokens.replace_link(l.clone()).await.expect("create link");
    }

    let removed = tokens
        .delete_links_for_user(user_id)
        .await
        .expect("delete the user's links");
    assert_eq!(removed, 2, "every purpose's link was deleted");
    for deleted in [&signup, &recovery] {
        assert!(
            tokens
                .redeem_link(&deleted.token_hash)
                .await
                .expect("redeem deleted")
                .is_none(),
            "a deleted link no longer redeems",
        );
    }
    assert!(
        tokens
            .redeem_link(&survivor.token_hash)
            .await
            .expect("redeem surviving")
            .is_some(),
        "another user's link survived the delete",
    );

    let expired = EmailLink {
        created_at: days(-2),
        expires_at: days(-1),
        ..link("expired-token", user_id, EmailLinkPurpose::Signup)
    };
    tokens
        .replace_link(expired.clone())
        .await
        .expect("create expired");
    let purged = tokens.purge_expired(present()).await.expect("purge");
    assert!(purged >= 1, "at least the expired token was purged");
    assert!(
        tokens
            .redeem_link(&expired.token_hash)
            .await
            .expect("redeem purged")
            .is_none(),
        "the expired token was removed by purge_expired",
    );
}

async fn sessions_crud_and_queries(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();
    let other_user = UserId::new();

    let sessions = &stores.sessions;
    let mk = |token: &str,
              owner: UserId,
              transport: SessionTransport,
              cool_down: Option<DateTime<Utc>>| Session {
        id: SessionId::new(),
        user_id: owner,
        token_hash: hash_token(token),
        transport,
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: Some("203.0.113.1".into()),
        user_agent: Some("agent".into()),
        recovery_cool_down_until: cool_down,
    };

    let keep = mk("keep", user_id, SessionTransport::Cookie, None);
    let other_a = mk("other-a", user_id, SessionTransport::Cookie, None);
    let other_b = mk("other-b", user_id, SessionTransport::Cookie, None);
    let neighbour = mk("neighbour", other_user, SessionTransport::Cookie, None);
    let cool_down_until = now + Duration::hours(24);
    let with_cool_down = mk(
        "cool-down",
        user_id,
        SessionTransport::Bearer,
        Some(cool_down_until),
    );

    for session in [&keep, &other_a, &other_b, &neighbour, &with_cool_down] {
        sessions
            .create_session(session.clone())
            .await
            .expect("create session");
    }

    let by_hash = sessions
        .find_session_by_token_hash(&hash_token("cool-down"))
        .await
        .expect("find by hash")
        .expect("session present");
    assert_eq!(by_hash.id, with_cool_down.id);
    assert_eq!(by_hash.transport, SessionTransport::Bearer);
    assert_eq!(by_hash.recovery_cool_down_until, Some(cool_down_until));
    assert_eq!(by_hash.ip.as_deref(), Some("203.0.113.1"));

    let by_id = sessions
        .find_session_by_id(with_cool_down.id)
        .await
        .expect("find by id")
        .expect("session present");
    assert_eq!(by_id.transport, SessionTransport::Bearer);
    assert_eq!(by_id.recovery_cool_down_until, Some(cool_down_until));

    let listed = sessions.list_for_user(user_id).await.expect("list");
    let listed_ids: std::collections::HashSet<_> = listed.iter().map(|s| s.id).collect();
    let expected: std::collections::HashSet<_> =
        [keep.id, other_a.id, other_b.id, with_cool_down.id].into();
    assert_eq!(
        listed_ids, expected,
        "list returns only this user's sessions"
    );
    for session in &listed {
        let expected = if session.id == with_cool_down.id {
            SessionTransport::Bearer
        } else {
            SessionTransport::Cookie
        };
        assert_eq!(
            session.transport, expected,
            "list keeps each session's transport"
        );
    }

    let removed = sessions
        .delete_sessions_for_user(user_id, Some(keep.id))
        .await
        .expect("delete others");
    assert_eq!(removed, 3, "every session except the exception was removed");
    let after = sessions.list_for_user(user_id).await.expect("list after");
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, keep.id);

    assert!(
        sessions
            .find_session_by_id(neighbour.id)
            .await
            .expect("find neighbour")
            .is_some()
    );

    let removed = sessions
        .delete_sessions_for_user(user_id, None)
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

async fn sessions_purge_expired(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;
    let expired = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("expired-session"),
        transport: SessionTransport::Cookie,
        created_at: now - Duration::hours(2),
        last_used_at: now - Duration::hours(2),
        expires_at: now - Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let live = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("live-session"),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
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

async fn session_touch_slides_deadline(stores: &ExpiringStores) {
    let created_at = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;
    let token_hash = hash_token("touch-slide");
    let original = Session {
        id: SessionId::new(),
        user_id,
        token_hash,
        transport: SessionTransport::Bearer,
        created_at,
        last_used_at: created_at,
        expires_at: days(365),
        ip: Some("203.0.113.9".into()),
        user_agent: Some("touch-agent".into()),
        recovery_cool_down_until: Some(days(516)),
    };
    sessions
        .create_session(original.clone())
        .await
        .expect("create session");

    let new_last_used_at = days(31);
    let new_expires_at = days(424);
    sessions
        .touch_session(original.id, new_last_used_at, new_expires_at)
        .await
        .expect("touch session");

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

    assert_eq!(by_id.id, original.id);
    assert_eq!(by_id.token_hash, original.token_hash);
    assert_eq!(by_id.created_at, original.created_at);
    assert_eq!(by_id.ip, original.ip);
    assert_eq!(by_id.user_agent, original.user_agent);
    assert_eq!(
        by_id.recovery_cool_down_until,
        original.recovery_cool_down_until,
    );

    sessions
        .delete_session(original.id)
        .await
        .expect("cleanup session");
}

async fn session_touch_does_not_resurrect(stores: &ExpiringStores) {
    let created_at = present();
    let user_id = UserId::new();

    let sessions = &stores.sessions;

    let phantom = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("touch-never-created"),
        transport: SessionTransport::Cookie,
        created_at,
        last_used_at: created_at,
        expires_at: days(365),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };
    sessions
        .touch_session(phantom.id, created_at, days(396))
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

    let revoked = Session {
        token_hash: hash_token("touch-after-delete"),
        transport: SessionTransport::Cookie,
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
        .touch_session(revoked.id, created_at, days(396))
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

async fn session_touch_races_revoke(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let raced: Vec<Session> = (0..RACERS)
        .map(|i| Session {
            id: SessionId::new(),
            user_id,
            token_hash: hash_token(&format!("touch-race-{i}")),
            transport: SessionTransport::Cookie,
            created_at: now,
            last_used_at: now,
            expires_at: days(365),
            ip: None,
            user_agent: None,
            recovery_cool_down_until: None,
        })
        .collect();
    for session in &raced {
        stores
            .sessions
            .create_session(session.clone())
            .await
            .expect("create raced session");
    }

    let mut tasks = Vec::new();
    for (i, session) in raced.iter().enumerate() {
        let id = session.id;
        let touch = {
            let sessions = stores.sessions.clone();
            async move {
                sessions
                    .touch_session(id, days(1), days(366))
                    .await
                    .expect("touch");
            }
        };
        let delete = {
            let sessions = stores.sessions.clone();
            async move { sessions.delete_session(id).await.expect("delete") }
        };
        // A delete started first lets its touch read the row before the delete
        // lands and write after it.
        if i % 2 == 0 {
            tasks.push(tokio::spawn(delete));
            tasks.push(tokio::spawn(touch));
        } else {
            tasks.push(tokio::spawn(touch));
            tasks.push(tokio::spawn(delete));
        }
    }
    for task in tasks {
        task.await.expect("race task");
    }

    for session in &raced {
        assert!(
            stores
                .sessions
                .find_session_by_id(session.id)
                .await
                .expect("find raced session")
                .is_none(),
            "a touch racing a delete must not resurrect the session",
        );
        assert!(
            stores
                .sessions
                .find_session_by_token_hash(&session.token_hash)
                .await
                .expect("find raced session by hash")
                .is_none(),
            "a touch racing a delete must not leave the session reachable by token hash",
        );
    }
    assert!(
        stores
            .sessions
            .list_for_user(user_id)
            .await
            .expect("list raced user")
            .is_empty(),
        "a touch racing a delete must not leave the session listed",
    );
}

const REVOKE_ROUNDS: usize = 8;

async fn session_revoke_races_creation(stores: &ExpiringStores) {
    let now = present();
    let user_id = UserId::new();

    let session = |token: String| Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token(&token),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: days(365),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let create = |session: Session| {
        let sessions = stores.sessions.clone();
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
        stores
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
        let sessions = stores.sessions.clone();
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

        let kept_resolves = stores
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

    let listed: std::collections::HashSet<_> = stores
        .sessions
        .list_for_user(user_id)
        .await
        .expect("list")
        .iter()
        .map(|s| s.id)
        .collect();
    for s in &created {
        let resolves = stores
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

    let removed = stores
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
            stores
                .sessions
                .find_session_by_token_hash(&s.token_hash)
                .await
                .expect("find by hash after second revoke")
                .is_none(),
            "no session resolves after the second revoke",
        );
    }
}

async fn passkeys_cool_down_round_trip(stores: &RecordStores) {
    let now = present();
    let user_id = UserId::new();

    let credential_id = b"conformance-passkey-id".to_vec();
    let passkey_blob = b"opaque-serialised-passkey-blob".to_vec();
    let cool_down_until = now + Duration::hours(24);
    let aaguid = uuid::Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
    let passkey = StoredPasskey {
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
        recovery_cool_down_until: Some(cool_down_until),
    };

    let passkeys = &stores.passkeys;
    passkeys
        .add_passkey(passkey.clone())
        .await
        .expect("create passkey");

    let by_id = passkeys
        .find_passkey_by_credential_id(&passkey.credential_id)
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
    assert_eq!(by_id.recovery_cool_down_until, Some(cool_down_until));

    let updated_blob = b"opaque-serialised-passkey-blob-v2".to_vec();
    let used_at = now + Duration::minutes(5);
    passkeys
        .record_passkey_use(
            &credential_id,
            PasskeyUse {
                passkey: updated_blob.clone(),
                backup_eligible: true,
                backup_state: true,
                used_at,
            },
        )
        .await
        .expect("record use");
    passkeys
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

    let listed = passkeys
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
        listed[0].recovery_cool_down_until,
        Some(cool_down_until),
        "cool-down preserved on update",
    );

    let other_user_id = UserId::new();
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
        recovery_cool_down_until: None,
    };
    assert_refused(
        passkeys.add_passkey(hijack).await,
        StorageErrorKind::Conflict,
        "duplicate credential id should error",
    );

    let still_owned = passkeys
        .find_passkey_by_credential_id(&credential_id)
        .await
        .expect("find by credential id after duplicate attempt")
        .expect("passkey still present");
    assert_eq!(
        still_owned.user_id, user_id,
        "the original owner is preserved after a duplicate-id attempt",
    );
}

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
        recovery_cool_down_until: None,
    }
}

async fn passkey_field_changes_compose(stores: &RecordStores) {
    let created_at = days(151);
    let used_at = days(152);
    let user_id = UserId::new();
    let passkeys = &stores.passkeys;
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
        passkeys
            .add_passkey(passkey(user_id, credential_id, created_at))
            .await
            .expect("add passkey");
        if use_first {
            passkeys
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }
        passkeys
            .set_passkey_name(credential_id, Some("laptop"))
            .await
            .expect("rename");
        if !use_first {
            passkeys
                .record_passkey_use(credential_id, used())
                .await
                .expect("record use");
        }

        let reread = passkeys
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

    passkeys
        .set_passkey_name(b"compose-use-first", None)
        .await
        .expect("clear name");
    let cleared = passkeys
        .find_passkey_by_credential_id(b"compose-use-first")
        .await
        .expect("find")
        .expect("present");
    assert_eq!(cleared.name, None, "a cleared name reads back as none");
    assert_eq!(cleared.last_used_at, Some(used_at));
}

async fn passkey_writes_refuse_missing_passkey(stores: &RecordStores) {
    let passkeys = &stores.passkeys;
    let missing = b"conformance-missing-passkey";
    assert_refused(
        passkeys
            .record_passkey_use(
                missing,
                PasskeyUse {
                    passkey: b"ghost-blob".to_vec(),
                    backup_eligible: false,
                    backup_state: false,
                    used_at: days(151),
                },
            )
            .await,
        StorageErrorKind::NotFound,
        "use of a missing passkey",
    );
    assert_refused(
        passkeys.set_passkey_name(missing, Some("ghost")).await,
        StorageErrorKind::NotFound,
        "rename of a missing passkey",
    );
    assert!(
        passkeys
            .find_passkey_by_credential_id(missing)
            .await
            .expect("find missing")
            .is_none(),
        "no write creates the passkey",
    );
}

async fn passkeys_bulk_delete_for_user(stores: &RecordStores) {
    let now = present();
    let target = UserId::new();
    let bystander = UserId::new();

    let passkeys = &stores.passkeys;
    let add = |user_id: UserId, credential_id: Vec<u8>| {
        let passkey = StoredPasskey {
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
            recovery_cool_down_until: None,
        };
        async move {
            passkeys.add_passkey(passkey).await.expect("add passkey");
        }
    };

    add(target, b"bulk-delete-target-passkey-1".to_vec()).await;
    add(target, b"bulk-delete-target-passkey-2".to_vec()).await;
    add(target, b"bulk-delete-target-passkey-3".to_vec()).await;
    let bystander_passkey = b"bulk-delete-bystander-passkey".to_vec();
    add(bystander, bystander_passkey.clone()).await;

    let count = |user_id: UserId| async move {
        passkeys
            .list_passkeys_for_user(user_id)
            .await
            .expect("count passkeys")
            .len()
    };
    assert_eq!(count(target).await, 3, "count covers the owner's passkeys");
    assert_eq!(count(bystander).await, 1, "count excludes other users");
    passkeys
        .delete_passkey(b"bulk-delete-target-passkey-3")
        .await
        .expect("delete one passkey");
    assert_eq!(count(target).await, 2, "count drops after a single removal");

    let removed = passkeys
        .delete_passkeys_for_user(target)
        .await
        .expect("delete passkeys for user");
    assert_eq!(
        removed, 2,
        "the return count equals the target user's passkey count",
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
        passkeys
            .list_passkeys_for_user(target)
            .await
            .expect("list target after delete")
            .is_empty(),
        "all of the target user's passkeys are removed",
    );

    let surviving = passkeys
        .list_passkeys_for_user(bystander)
        .await
        .expect("list bystander after delete");
    assert_eq!(surviving.len(), 1, "another user's passkey survives");
    assert_eq!(surviving[0].credential_id, bystander_passkey);
}

async fn passkey_registration_round_trip(stores: &ExpiringStores) {
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

async fn passkey_registration_delete_for_user(stores: &ExpiringStores) {
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

async fn passkey_registration_delete_races_creation(stores: &ExpiringStores) {
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

async fn passkey_authentication_single_use(stores: &ExpiringStores) {
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

async fn passkey_challenge_purge_expired(stores: &ExpiringStores) {
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

async fn single_use_under_concurrency(stores: &ExpiringStores) {
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

async fn owner_indexes_track_removals(stores: &ExpiringStores) {
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
        ip: None,
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

async fn absent_lookups_return_none(stores: &ExpiringStores) {
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

async fn inserts_refuse_duplicate_keys(stores: &ExpiringStores) {
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
        ip: None,
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
