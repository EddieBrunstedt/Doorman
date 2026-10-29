use doorman_core::email::MAX_EMAIL_ADDRESS_LEN;
use doorman_core::passkey::{MAX_CREDENTIAL_ID_LEN, MAX_PASSKEY_NAME_LEN};
use doorman_core::session::{SessionContext, hash_token};
use doorman_core::storage::{
    EmailLink, EmailLinkPurpose, ExpiringStores, PasskeyChallengeId, RecordStores,
    RegistrationPurpose, Session, SessionId, SessionTransport, StoredPasskeyRegistration, UserId,
};

use crate::fixtures::{days, passkey, present, user};

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

pub(crate) async fn records_hold_values_at_core_limits(stores: &RecordStores) {
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

pub(crate) async fn expiring_hold_values_at_core_limits(stores: &ExpiringStores) {
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
            ip: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                .parse()
                .expect("client IP"),
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
