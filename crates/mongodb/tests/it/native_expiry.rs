use chrono::{DateTime, Duration, Utc};
use doorman_core::session::hash_token;
use doorman_core::storage::{
    AuthenticationPurpose, EmailLink, EmailLinkPurpose, PasskeyChallengeId, RegistrationPurpose,
    Session, SessionId, SessionTransport, StoredPasskeyAuthentication, StoredPasskeyRegistration,
    UserId,
};
use doorman_mongodb::MongoDbStorage;
use mongodb::Database;
use mongodb::bson::{Bson, Document, doc};
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

async fn expiry_index_seconds(db: &Database, collection: &str) -> Option<u64> {
    let mut cursor = db
        .collection::<Document>(collection)
        .list_indexes()
        .await
        .expect("list indexes");
    while cursor.advance().await.expect("next index") {
        let index = cursor.deserialize_current().expect("index model");
        if index.keys == doc! { "expires_at": 1 } {
            return index
                .options
                .and_then(|options| options.expire_after)
                .map(|after| after.as_secs());
        }
    }
    None
}

async fn stored_expires_at(db: &Database, collection: &str, filter: Document) -> Bson {
    db.collection::<Document>(collection)
        .find_one(filter)
        .await
        .expect("find row")
        .expect("row exists")
        .get("expires_at")
        .cloned()
        .expect("expires_at field")
}

fn bson_date(at: DateTime<Utc>) -> Bson {
    Bson::DateTime(mongodb::bson::DateTime::from_millis(at.timestamp_millis()))
}

#[tokio::test]
async fn every_row_expires_at_its_deadline() {
    let node = Mongo::default()
        .start()
        .await
        .expect("start mongodb container");
    let host = node.get_host().await.expect("container host");
    let port = node
        .get_host_port_ipv4(27017)
        .await
        .expect("container port");
    let client = mongodb::Client::with_uri_str(format!("mongodb://{host}:{port}/"))
        .await
        .expect("connect to mongodb");
    let db = client.database("doorman_native_expiry");
    let storage = MongoDbStorage::new(db.clone());
    storage.ensure_indexes().await.expect("ensure indexes");
    let stores = storage.expiring();
    let now = Utc::now();

    for collection in [
        "sessions",
        "email_links",
        "passkey_registrations",
        "passkey_authentications",
    ] {
        assert_eq!(
            expiry_index_seconds(&db, collection).await,
            Some(0),
            "{collection} drops a row once its expires_at passes",
        );
    }

    let session = Session {
        id: SessionId::new(),
        user_id: UserId::new(),
        token_hash: hash_token("native-expiry-session"),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: now + Duration::hours(1),
        ip: "192.0.2.1".parse().expect("client IP"),
        user_agent: None,
        recovery_cool_down_until: None,
    };
    let by_id = doc! { "_id": session.id.0.to_string() };
    stores
        .sessions
        .create_session(session.clone())
        .await
        .expect("create session");
    assert_eq!(
        stored_expires_at(&db, "sessions", by_id.clone()).await,
        bson_date(session.expires_at),
        "the session's deadline is a date the expiry index reads",
    );

    let slid = now + Duration::hours(2);
    stores
        .sessions
        .touch_session(session.id, now, slid)
        .await
        .expect("touch session");
    assert_eq!(
        stored_expires_at(&db, "sessions", by_id).await,
        bson_date(slid),
        "the slid deadline is a date the expiry index reads",
    );

    let link = EmailLink {
        token_hash: hash_token("native-expiry-link"),
        user_id: UserId::new(),
        purpose: EmailLinkPurpose::Signup,
        owner_email: None,
        new_email: None,
        created_at: now,
        expires_at: now + Duration::minutes(30),
    };
    stores
        .email_links
        .replace_link(link.clone())
        .await
        .expect("replace link");
    assert_eq!(
        stored_expires_at(
            &db,
            "email_links",
            doc! { "user_id": link.user_id.0.to_string() },
        )
        .await,
        bson_date(link.expires_at),
        "the email link's deadline is a date the expiry index reads",
    );

    let registration = StoredPasskeyRegistration {
        id: PasskeyChallengeId::new(),
        purpose: RegistrationPurpose::Signup,
        user_id: UserId::new(),
        state: b"registration-state".to_vec(),
        owner_email: None,
        created_at: now,
        expires_at: now + Duration::minutes(5),
        recovery_cool_down_until: None,
    };
    stores
        .passkey_challenges
        .put_registration(registration.clone())
        .await
        .expect("put registration");
    assert_eq!(
        stored_expires_at(
            &db,
            "passkey_registrations",
            doc! { "_id": registration.id.0.to_string() },
        )
        .await,
        bson_date(registration.expires_at),
        "the passkey registration's deadline is a date the expiry index reads",
    );

    let authentication = StoredPasskeyAuthentication {
        id: PasskeyChallengeId::new(),
        purpose: AuthenticationPurpose::Login,
        state: b"authentication-state".to_vec(),
        created_at: now,
        expires_at: now + Duration::minutes(4),
    };
    stores
        .passkey_challenges
        .put_authentication(authentication.clone())
        .await
        .expect("put authentication");
    assert_eq!(
        stored_expires_at(
            &db,
            "passkey_authentications",
            doc! { "_id": authentication.id.0.to_string() },
        )
        .await,
        bson_date(authentication.expires_at),
        "the passkey authentication's deadline is a date the expiry index reads",
    );
}
