//! The five per-trait store implementations.
//!
//! Each module implements one `doorman-core` storage trait over the shared
//! [`DynamoClient`](crate::client::DynamoClient): the ephemeral stores lean on
//! native TTL plus the atomic delete-and-return `take`, while the
//! system-of-record stores ([`user`], [`passkey_cred`]) use conditional writes
//! for the uniqueness and existence guarantees a relational backend gives for
//! free.

pub(crate) mod passkey_chal;
pub(crate) mod passkey_cred;
pub(crate) mod session;
pub(crate) mod user;
pub(crate) mod verification;
