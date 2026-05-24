//! Core authentication primitives for the `bauth` library.
//!
//! This crate is intentionally framework-agnostic: it defines the storage,
//! clock, email, and audit traits that a host application implements. The
//! session manager and in-memory implementations land in follow-up commits.

pub mod audit;
pub mod clock;
pub mod email;
pub mod error;
pub mod storage;

pub use error::{BoxError, EmailError, EmailResult, Error, Result, StorageError, StorageResult};
