// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod client;
mod keys;
mod rate_limit;
mod scripts;
mod stores;
mod table;

use std::sync::Arc;

use doorman_core::clock::{Clock, SystemClock};
use doorman_core::error::StorageResult;
use doorman_core::rate_limit::RateLimiter;
use doorman_core::storage::ExpiringStores;
use redis::IntoConnectionInfo;
use redis::aio::ConnectionManager;
use redis::cluster::ClusterClient;

use crate::client::{Connection, RedisClient};

pub use crate::keys::{InvalidNamespace, Namespace};

#[derive(Clone)]
pub struct RedisStorage {
    client: RedisClient,
}

impl RedisStorage {
    pub async fn connect(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        Self::from_client(client).await
    }

    // Takes node addresses rather than a host-built client: a client set to read from replicas
    // could miss a write that finished before the read.
    pub async fn connect_cluster<T: IntoConnectionInfo>(
        nodes: impl IntoIterator<Item = T>,
    ) -> Result<Self, redis::RedisError> {
        let connection = ClusterClient::new(nodes)?.get_async_connection().await?;
        Ok(Self::from_connection(Connection::Cluster(connection)))
    }

    pub async fn from_client(client: redis::Client) -> Result<Self, redis::RedisError> {
        let manager = client.get_connection_manager().await?;
        Ok(Self::from_connection_manager(manager))
    }

    pub fn from_connection_manager(manager: ConnectionManager) -> Self {
        Self::from_connection(Connection::Standalone(manager))
    }

    fn from_connection(connection: Connection) -> Self {
        Self {
            client: RedisClient::new(connection, &Namespace::default()),
        }
    }

    pub fn with_namespace(mut self, namespace: Namespace) -> Self {
        self.client = self.client.with_namespace(&namespace);
        self
    }

    pub async fn ping(&self) -> StorageResult<()> {
        self.client.ping().await
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
