//! Core authentication primitives for the `bauth` library.
//!
//! This crate is intentionally framework-agnostic: it defines the storage,
//! clock, email, and audit traits that a host application implements, plus
//! the [`SessionManager`](crate::session::SessionManager) that drives session
//! creation, validation, and revocation against those traits.
//!
//! The companion crate `bauth-axum` provides an HTTP layer on top.

pub mod audit;
pub mod clock;
pub mod email;
pub mod error;
pub mod magic_link;
pub mod memory;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod password_auth;
pub mod prelude;
pub mod rate_limit;
pub mod session;
pub mod storage;

pub use error::*;
