use chrono::{DateTime, Duration, TimeZone, Utc};
use doorman_core::error::{StorageErrorKind, StorageResult};
use doorman_core::session::hash_token;
use doorman_core::storage::{EmailLink, EmailLinkPurpose, StoredPasskey, User, UserId, UserStatus};

// After any real date a run happens on: a backend that expires rows by its own
// clock must not drop a fixture before the check reaches it.
pub(crate) fn present() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

pub(crate) fn days(n: i64) -> DateTime<Utc> {
    present() + Duration::days(n)
}

#[track_caller]
pub(crate) fn assert_refused<T: std::fmt::Debug>(
    result: StorageResult<T>,
    kind: StorageErrorKind,
    what: &str,
) {
    match result {
        Err(err) => assert_eq!(err.kind(), kind, "{what}: wrong error kind ({err})"),
        Ok(value) => panic!("{what}: expected {kind:?}, got Ok({value:?})"),
    }
}

pub(crate) fn user(id: UserId, email: &str) -> User {
    User {
        id,
        email: Some(email.to_string()),
        signed_up_at: None,
        status: UserStatus::Active,
        created_at: present(),
        updated_at: present(),
    }
}

pub(crate) const RACERS: usize = 64;

pub(crate) const REVOKE_ROUNDS: usize = 8;

pub(crate) fn link(raw: &str, user_id: UserId, purpose: EmailLinkPurpose) -> EmailLink {
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

pub(crate) fn passkey(
    user_id: UserId,
    credential_id: &[u8],
    created_at: DateTime<Utc>,
) -> StoredPasskey {
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
