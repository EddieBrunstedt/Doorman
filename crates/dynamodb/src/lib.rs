//! Amazon DynamoDB storage adapter for `doorman-core`.
//!
//! `doorman-dynamodb` fills **all five** storage traits against a single
//! DynamoDB table, so an AWS-native or Lambda/serverless deployment can run
//! doorman with neither a SQL server nor a Redis instance. It suits exactly the
//! environments where a managed, pay-per-request key-value store is already the
//! path of least resistance.
//!
//! ## How it maps onto DynamoDB
//!
//! Everything lives in one table addressed by a single partition key, with two
//! global secondary indexes for the secondary access patterns and DynamoDB's
//! native per-item TTL for the ephemeral records. The item layout is documented
//! on the (private) `model` module. The notable design points:
//!
//! - **Atomic single-use.** `consume_token`, `take_registration`, and
//!   `take_authentication` are a `DeleteItem` with `ReturnValues=ALL_OLD`:
//!   DynamoDB serializes writes per item, so exactly one concurrent caller
//!   observes the value.
//! - **Email uniqueness.** A GSI can enforce no constraints and is only
//!   eventually consistent, so a user's email is guarded by a strongly-consistent
//!   companion item written in the same transaction as the user — which also
//!   serves as the email → user lookup. Every other secondary lookup uses a GSI,
//!   which DynamoDB maintains automatically (no dangling-index bookkeeping).
//! - **Expiry.** Native TTL deletion lags by up to ~48h and is a memory
//!   backstop only: the stores filter `expires_at > now` on read and
//!   `purge_expired` performs the authoritative, immediate reclamation.
//!
//! ## Eventual consistency
//!
//! Reads of the system-of-record (users, passkey credentials) are
//! strongly-consistent. The per-user collection listings and the token-hash
//! session lookup read a GSI, which is eventually consistent: a row is normally
//! visible within milliseconds of its write but not guaranteed to be on the very
//! next read. The managers re-resolve and re-filter, so this never yields an
//! incorrect result — only, rarely, a momentarily stale one.
//!
//! ## Usage
//!
//! The adapter takes a caller-built [`aws_sdk_dynamodb::Client`], so the host
//! owns region, credentials, retry, and endpoint configuration:
//!
//! ```ignore
//! use doorman_dynamodb::DynamoDbStorage;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = aws_config::load_from_env().await;
//! let client = aws_sdk_dynamodb::Client::new(&config);
//!
//! let storage = DynamoDbStorage::new(client, "doorman");
//! storage.create_table().await?; // idempotent; safe on every boot
//!
//! let composite = storage.all_stores();
//! # let _ = composite;
//! # Ok(()) }
//! ```

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test helpers.
#![deny(missing_docs)]

mod client;
mod model;
mod stores;

use std::sync::Arc;

use doorman_core::error::StorageResult;
use doorman_core::storage::{
    PasskeyChallengeStore, PasskeyCredentialStore, SessionStore, Storage, UserStore,
    VerificationTokenStore,
};

use crate::client::DynamoClient;

/// Handle to a DynamoDB backend for doorman's storage.
///
/// Construct one at startup with [`new`](Self::new) from a configured AWS SDK
/// client and a table name, provision the table once with
/// [`create_table`](Self::create_table), then either hand
/// [`all_stores`](Self::all_stores) to `AuthService::builder` or pull individual
/// stores when wiring managers by hand. Cloning is cheap — the SDK client is
/// reference-counted internally.
#[derive(Clone)]
pub struct DynamoDbStorage {
    client: DynamoClient,
}

impl DynamoDbStorage {
    /// Build a storage handle over `client`, targeting `table_name`.
    ///
    /// The client carries the host's region, credentials, endpoint, and retry
    /// configuration; this adapter issues operations through it unchanged.
    pub fn new(client: aws_sdk_dynamodb::Client, table_name: impl Into<String>) -> Self {
        Self {
            client: DynamoClient::new(client, table_name.into()),
        }
    }

    /// The configured table name.
    pub fn table_name(&self) -> &str {
        self.client.table()
    }

    /// Provision the table, its two secondary indexes, and native TTL.
    ///
    /// Idempotent and safe to call on every boot: an already-existing table is a
    /// no-op. Creates the table with on-demand (`PAY_PER_REQUEST`) billing, so
    /// no throughput needs provisioning. A host that manages its own
    /// infrastructure (Terraform, CloudFormation, CDK) can skip this and create
    /// the table out of band — it must use a single string partition key `pk`,
    /// two all-projection GSIs (`lookup-index` on `gsi1pk`, `owner-index` on
    /// `gsi2pk`), and TTL enabled on the `ttl` attribute.
    pub async fn create_table(&self) -> StorageResult<()> {
        self.client.ensure_table().await
    }

    /// Build a [`Storage`] populated with every per-trait store backed by this
    /// table — the single-backend shortcut for hosts keeping everything in
    /// DynamoDB.
    pub fn all_stores(&self) -> Storage {
        Storage {
            users: self.user_store(),
            sessions: self.session_store(),
            verification_tokens: self.verification_token_store(),
            passkey_credentials: self.passkey_credential_store(),
            passkey_challenges: self.passkey_challenge_store(),
        }
    }

    /// The user store backed by this table.
    pub fn user_store(&self) -> Arc<dyn UserStore> {
        Arc::new(stores::user::DynamoUserStore::new(self.client.clone()))
    }

    /// The session store backed by this table.
    pub fn session_store(&self) -> Arc<dyn SessionStore> {
        Arc::new(stores::session::DynamoSessionStore::new(
            self.client.clone(),
        ))
    }

    /// The verification-token store backed by this table.
    pub fn verification_token_store(&self) -> Arc<dyn VerificationTokenStore> {
        Arc::new(stores::verification::DynamoVerificationTokenStore::new(
            self.client.clone(),
        ))
    }

    /// The passkey-credential store backed by this table.
    pub fn passkey_credential_store(&self) -> Arc<dyn PasskeyCredentialStore> {
        Arc::new(stores::passkey_cred::DynamoPasskeyCredentialStore::new(
            self.client.clone(),
        ))
    }

    /// The passkey-challenge store backed by this table.
    pub fn passkey_challenge_store(&self) -> Arc<dyn PasskeyChallengeStore> {
        Arc::new(stores::passkey_chal::DynamoPasskeyChallengeStore::new(
            self.client.clone(),
        ))
    }
}
