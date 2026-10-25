use std::net::TcpListener;
use std::time::Duration;

use chrono::Utc;
use doorman_core::session::hash_token;
use doorman_core::storage::{
    Session, SessionId, SessionTransport, StoredPasskey, User, UserId, UserStatus,
};
use doorman_mongodb::MongoDbStorage;
use mongodb::bson::doc;
use mongodb::{Client, Database};
use testcontainers_modules::mongo::Mongo;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::core::{IntoContainerPort, Mount};
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const DATABASE: &str = "doorman_replica_set";

fn free_ports() -> [u16; 3] {
    let listeners = [(); 3].map(|()| TcpListener::bind("127.0.0.1:0").expect("bind a free port"));
    listeners.map(|listener| listener.local_addr().expect("bound address").port())
}

async fn direct(port: u16) -> Client {
    Client::with_uri_str(format!("mongodb://127.0.0.1:{port}/?directConnection=true"))
        .await
        .expect("connect to one member")
}

async fn until_up(member: &Client) {
    while member
        .database("admin")
        .run_command(doc! { "ping": 1 })
        .await
        .is_err()
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn until_replicated(member: &Database, collection: &str, rows: u64) {
    let collection = member.collection::<mongodb::bson::Document>(collection);
    while !collection
        .count_documents(doc! {})
        .await
        .is_ok_and(|count| count >= rows)
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// The host's client sends every read it can to one secondary whose replication is stalled, so a
// read that reaches it misses every write made after the stall. Core checks a login against the
// user, and a request against its session, by reads like these; each must see the write before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_see_every_finished_write_when_the_host_prefers_secondaries() {
    // Each member listens inside the container on the port it is published on, so the addresses
    // the replica set advertises reach it from the host too.
    let ports = free_ports();
    let start_members = ports
        .iter()
        .enumerate()
        .map(|(i, port)| {
            format!(
                "mkdir -p /data/db/{i} && mongod --replSet rs --bind_ip_all --port {port} --dbpath /data/db/{i} &"
            )
        })
        .collect::<String>();
    let mut node = Mongo::default()
        .with_mount(Mount::tmpfs_mount("/data/db"))
        .with_cmd(["bash", "-c", &format!("{start_members} wait")]);
    for port in ports {
        node = node.with_mapped_port(port, port.tcp());
    }
    let _node = node.start().await.expect("start mongodb container");

    let [primary, _, lagging] = ports;
    for port in ports {
        until_up(&direct(port).await).await;
    }
    direct(primary)
        .await
        .database("admin")
        .run_command(doc! {
            "replSetInitiate": {
                "_id": "rs",
                "members": [
                    { "_id": 0, "host": format!("127.0.0.1:{}", ports[0]), "priority": 2 },
                    { "_id": 1, "host": format!("127.0.0.1:{}", ports[1]), "priority": 1 },
                    {
                        "_id": 2,
                        "host": format!("127.0.0.1:{}", ports[2]),
                        "priority": 0,
                        "tags": { "role": "lagging" },
                    },
                ],
            },
        })
        .await
        .expect("initiate replica set");

    let client = Client::with_uri_str(format!(
        "mongodb://127.0.0.1:{}/?replicaSet=rs&readPreference=secondary&readPreferenceTags=role:lagging&w=1&readConcernLevel=local",
        ports.map(|port| port.to_string()).join(",127.0.0.1:"),
    ))
    .await
    .expect("connect to replica set");
    let storage = MongoDbStorage::new(client.database(DATABASE));
    let stores = storage.all_stores();
    let (users, passkeys, sessions) = (
        &stores.records.users,
        &stores.records.passkeys,
        &stores.expiring.sessions,
    );

    let now = Utc::now();
    let user_id = UserId::new();
    users
        .create_user(User {
            id: user_id,
            email: Some("alice@example.com".into()),
            signed_up_at: Some(now),
            status: UserStatus::Active,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create user");
    let credential_id = b"replica-set-passkey".to_vec();
    passkeys
        .add_passkey(StoredPasskey {
            credential_id: credential_id.clone(),
            user_id,
            passkey: b"opaque-serialised-passkey-blob".to_vec(),
            name: None,
            created_at: now,
            last_used_at: None,
            aaguid: None,
            transports: Vec::new(),
            backup_eligible: false,
            backup_state: false,
            recovery_cool_down_until: None,
        })
        .await
        .expect("add passkey");
    let session = Session {
        id: SessionId::new(),
        user_id,
        token_hash: hash_token("replica-set-session"),
        transport: SessionTransport::Cookie,
        created_at: now,
        last_used_at: now,
        expires_at: now + chrono::Duration::hours(1),
        ip: None,
        user_agent: None,
        recovery_cool_down_until: None,
    };
    sessions
        .create_session(session.clone())
        .await
        .expect("create session");

    let lagging_member = direct(lagging).await;
    let lagging_db = lagging_member.database(DATABASE);
    for collection in ["users", "passkeys", "sessions"] {
        until_replicated(&lagging_db, collection, 1).await;
    }
    lagging_member
        .database("admin")
        .run_command(doc! { "fsync": 1, "lock": true })
        .await
        .expect("stall replication to the lagging member");

    let disabled_at = Utc::now();
    users
        .set_user_status(
            user_id,
            UserStatus::Disabled { at: disabled_at },
            disabled_at,
        )
        .await
        .expect("disable user");
    sessions
        .delete_session(session.id)
        .await
        .expect("revoke session");
    passkeys
        .delete_passkey(&credential_id)
        .await
        .expect("remove passkey");

    let user = users
        .find_user_by_id(user_id)
        .await
        .expect("find user")
        .expect("user present");
    assert!(
        matches!(user.status, UserStatus::Disabled { .. }),
        "a finished disable is seen, not {:?}",
        user.status,
    );
    assert_eq!(
        sessions
            .find_session_by_token_hash(&session.token_hash)
            .await
            .expect("find session by token hash"),
        None,
        "a revoked session no longer resolves",
    );
    assert_eq!(
        sessions
            .find_session_by_id(session.id)
            .await
            .expect("find session by id"),
        None,
        "a revoked session is not read again",
    );
    assert!(
        sessions
            .list_for_user(user_id)
            .await
            .expect("list sessions")
            .is_empty(),
        "a revoked session is not listed",
    );
    assert!(
        passkeys
            .find_passkey_by_credential_id(&credential_id)
            .await
            .expect("find passkey")
            .is_none(),
        "a removed passkey is not found",
    );
    assert!(
        passkeys
            .list_passkeys_for_user(user_id)
            .await
            .expect("list passkeys")
            .is_empty(),
        "a removed passkey is not listed",
    );
}
