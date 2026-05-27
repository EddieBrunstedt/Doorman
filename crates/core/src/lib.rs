//! Core authentication primitives for bauth.
//!
//! `bauth-axum` is the supported user-facing integration. This crate stays
//! framework-agnostic so the auth logic can be tested and reasoned about
//! without an HTTP router attached. It owns the storage, clock, email,
//! audit, and rate-limiter traits plus the managers that implement each
//! auth flow.

pub mod audit;
pub mod clock;
pub mod email;
pub mod error;
pub mod magic_link;
pub mod memory;
pub mod oauth;
pub mod passkey;
pub mod prelude;
pub mod rate_limit;
pub mod session;
pub mod storage;

pub use error::*;
