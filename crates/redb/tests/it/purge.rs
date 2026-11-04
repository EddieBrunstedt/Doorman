use chrono::{DateTime, Duration, TimeZone as _, Utc};
use doorman_core::purge::PurgeSummary;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AuthenticationPurpose, DpopProofId, EmailLink, EmailLinkPurpose, ExpiringStores,
    PasskeyChallengeId, RegistrationPurpose, Session, SessionId, SessionTransport,
    StoredPasskeyAuthentication, StoredPasskeyRegistration, UsedDpopProof, UserId,
};
use doorman_redb::RedbStorage;
use redb::{
    Database, ReadableDatabase as _, ReadableTable as _, ReadableTableMetadata as _,
    TableDefinition, TableHandle as _,
};

const ROW_TABLES: [&str; 5] = [
    "sessions",
    "email_links",
    "pkregs",
    "pkauths",
    "dpop_proofs",
];

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0)
        .single()
        .expect("valid timestamp")
}

// One row in every expiring table, each with its own owner, so no email link replaces another.
async fn seed(stores: &ExpiringStores, tag: &str, expires_at: DateTime<Utc>) -> SessionId {
    let created_at = expires_at - Duration::hours(2);
    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token(&format!("{tag}-session")),
        transport: SessionTransport::Cookie,
        created_at,
        last_used_at: created_at,
        expires_at,
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    stores
        .sessions
        .create_session(session.clone())
        .await
        .expect("session");
    stores
        .email_links
        .replace_link(EmailLink {
            token_hash: hash_token(&format!("{tag}-link")),
            user_id: UserId::new(),
            purpose: EmailLinkPurpose::Recovery,
            owner_email: None,
            new_email: None,
            created_at,
            expires_at,
        })
        .await
        .expect("email link");
    stores
        .passkey_challenges
        .put_registration(StoredPasskeyRegistration {
            id: PasskeyChallengeId::new(),
            purpose: RegistrationPurpose::AddPasskey,
            user_id: UserId::new(),
            state: vec![1, 2, 3],
            owner_email: None,
            created_at,
            expires_at,
            recovery_cool_down_until: None,
        })
        .await
        .expect("passkey registration");
    stores
        .passkey_challenges
        .put_authentication(StoredPasskeyAuthentication {
            id: PasskeyChallengeId::new(),
            purpose: AuthenticationPurpose::Login,
            state: vec![4, 5, 6],
            created_at,
            expires_at,
        })
        .await
        .expect("passkey authentication");
    stores
        .dpop_proofs
        .use_proof(UsedDpopProof {
            id: DpopProofId(hash_token(&format!("{tag}-proof")).0),
            expires_at,
        })
        .await
        .expect("used DPoP proof");
    session.id
}

fn garble_every_row(db: &Database) {
    let wtxn = db.begin_write().expect("write");
    for name in ROW_TABLES {
        let mut rows = wtxn
            .open_table(TableDefinition::<&str, &[u8]>::new(name))
            .expect("row table");
        let keys: Vec<String> = rows
            .iter()
            .expect("rows")
            .map(|row| row.expect("row").0.value().to_owned())
            .collect();
        for key in keys {
            rows.insert(key.as_str(), b"\xffnot a row".as_slice())
                .expect("garble");
        }
    }
    wtxn.commit().expect("commit");
}

fn row_counts(db: &Database) -> [u64; 5] {
    let rtxn = db.begin_read().expect("read");
    ROW_TABLES.map(|name| {
        rtxn.open_table(TableDefinition::<&str, &[u8]>::new(name))
            .expect("row table")
            .len()
            .expect("len")
    })
}

fn assert_purged_one_of_each(summary: &PurgeSummary) {
    assert_eq!(summary.failures().count(), 0, "{summary:?}");
    assert_eq!(summary.sessions.as_ref().ok(), Some(&1));
    assert_eq!(summary.email_links.as_ref().ok(), Some(&1));
    assert_eq!(summary.passkey_challenges.as_ref().ok(), Some(&2));
    assert_eq!(summary.dpop_proofs.as_ref().ok(), Some(&1));
}

#[tokio::test]
async fn purge_removes_rows_that_no_longer_decode_at_their_deadline() {
    let dir = tempfile::tempdir().expect("temp dir");
    let storage = RedbStorage::open(dir.path().join("purge.redb")).expect("open redb");
    let stores = storage.expiring();
    let db = storage.database();

    let garbled = seed(&stores, "garbled", now() + Duration::hours(1)).await;
    garble_every_row(&db);
    seed(&stores, "expired", now() - Duration::hours(1)).await;
    assert!(
        stores.sessions.find_session_by_id(garbled).await.is_err(),
        "a garbled row no longer decodes",
    );

    let before_deadline = stores.purge_all_expired(now()).await;
    assert_purged_one_of_each(&before_deadline);
    assert_eq!(
        row_counts(&db),
        [1; 5],
        "the garbled rows outlive the purge"
    );

    let past_deadline = stores.purge_all_expired(now() + Duration::hours(2)).await;
    assert_purged_one_of_each(&past_deadline);

    let rtxn = db.begin_read().expect("read");
    for table in rtxn.list_tables().expect("tables") {
        let name = table.name().to_owned();
        let len = rtxn
            .open_untyped_table(table)
            .expect("table")
            .len()
            .expect("len");
        assert_eq!(len, 0, "{name} still holds an entry");
    }
}
