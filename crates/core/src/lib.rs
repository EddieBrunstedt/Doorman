//! Core authentication primitives for doorman.
//!
//! `doorman-axum` is the supported user-facing integration. This crate stays
//! framework-agnostic so the auth logic can be tested and reasoned about
//! without an HTTP router attached. It owns the storage, clock, email,
//! audit, and rate-limiter traits plus the managers that implement each
//! auth flow.

// Every public item in this library carries rustdoc. Scoped to this crate on
// purpose — kept out of the workspace lints so the requirement never fires on
// test/bench helpers.
#![deny(missing_docs)]
// Lock in rustdoc quality alongside the coverage above: broken intra-doc links,
// malformed code blocks, bare URLs, and the rest of the rustdoc lint group warn
// here and become hard errors under the `-D warnings` doc gate.
#![warn(rustdoc::all)]

pub mod account;
pub mod assembly;
pub mod audit;
pub mod cache;
pub mod clock;
pub mod context;
pub mod email;
pub mod encoding;
pub mod error;
pub mod memory;
pub mod metrics;
pub mod operator;
pub mod passkey;
pub mod prelude;
pub mod purge;
pub mod rate_limit;
pub mod reauth;
pub mod recovery;
pub mod session;
pub mod signup;
pub mod storage;
pub mod token;
pub mod verification;

pub use error::*;
