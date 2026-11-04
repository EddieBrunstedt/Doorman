// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod client;
mod eviction;
mod keys;
mod rate_limit;
mod rows;
mod scripts;
mod stores;
mod table;

use std::sync::Arc;

use doorman_core::clock::{Clock, SystemClock};
use doorman_core::error::{StorageError, StorageResult};
use doorman_core::rate_limit::RateLimiter;
use doorman_core::storage::ExpiringStores;
use redis::IntoConnectionInfo;
use redis::aio::ConnectionManager;
use redis::cluster::ClusterClient;

use crate::client::{Connection, RedisClient};

pub use crate::eviction::EvictionPolicyError;
pub use crate::keys::{Namespace, NamespaceError};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Redis(#[from] redis::RedisError),
    #[error(transparent)]
    EvictionPolicy(#[from] EvictionPolicyError),
}

#[derive(Clone)]
pub struct RedisStorage {
    client: RedisClient,
}

impl RedisStorage {
    pub async fn connect(url: &str) -> Result<Self, ConnectError> {
        let client = redis::Client::open(url)?;
        Self::from_client(client).await
    }

    // Takes node addresses rather than a host-built client: a client set to read from replicas
    // could miss a write that finished before the read.
    pub async fn connect_cluster<T: IntoConnectionInfo>(
        nodes: impl IntoIterator<Item = T>,
    ) -> Result<Self, ConnectError> {
        let connection = ClusterClient::new(nodes)?.get_async_connection().await?;
        Self::from_connection(Connection::Cluster(connection)).await
    }

    pub async fn from_client(client: redis::Client) -> Result<Self, ConnectError> {
        let manager = client.get_connection_manager().await?;
        Self::from_connection_manager(manager).await
    }

    pub async fn from_connection_manager(manager: ConnectionManager) -> Result<Self, ConnectError> {
        Self::from_connection(Connection::Standalone(manager)).await
    }

    async fn from_connection(connection: Connection) -> Result<Self, ConnectError> {
        let client = RedisClient::new(connection, &Namespace::default());
        eviction::check(&client).await?;
        Ok(Self { client })
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.client = self.client.with_namespace(&namespace);
        self
    }

    // Checks the policy again, since it can be changed while the host runs.
    pub async fn ping(&self) -> StorageResult<()> {
        eviction::check(&self.client)
            .await
            .map_err(StorageError::new)
    }

    pub fn expiring(&self) -> ExpiringStores {
        ExpiringStores {
            sessions: Arc::new(stores::session::RedisSessionStore::new(self.client.clone())),
            email_links: Arc::new(stores::email_link::RedisEmailLinkStore::new(
                self.client.clone(),
            )),
            passkey_challenges: Arc::new(stores::passkey_chal::RedisPasskeyChallengeStore::new(
                self.client.clone(),
            )),
            dpop_proofs: Arc::new(stores::dpop_proof::RedisDpopProofStore::new(
                self.client.clone(),
            )),
        }
    }

    pub fn rate_limiter(&self) -> Arc<dyn RateLimiter> {
        self.rate_limiter_with_clock(Arc::new(SystemClock))
    }

    pub fn rate_limiter_with_clock(&self, clock: Arc<dyn Clock>) -> Arc<dyn RateLimiter> {
        Arc::new(rate_limit::RedisRateLimiter::new(
            self.client.clone(),
            clock,
        ))
    }
}
