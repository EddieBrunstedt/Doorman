//! Core authentication primitives for bauth.
//!
//! `bauth-axum` is the supported user-facing integration. This crate stays
//! framework-agnostic so the auth logic can be tested and reasoned about
//! without an HTTP router attached. It owns the storage, clock, email,
//! audit, and rate-limiter traits plus the managers that implement each
//! auth flow.

pub mod account;
pub mod audit;
pub mod clock;
pub mod context;
pub mod email;
pub mod error;
pub mod memory;
pub mod passkey;
pub mod prelude;
pub mod purge;
pub mod rate_limit;
pub mod recovery;
pub mod session;
pub mod signup;
pub mod storage;
pub mod token;
pub mod verification;

pub use error::*;
