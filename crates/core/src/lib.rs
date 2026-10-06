// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

pub mod account;
pub mod assembly;
mod assertion;
pub mod audit;
mod challenge;
pub mod clock;
mod context;
pub mod email;
pub mod encoding;
pub mod error;
mod link;
pub mod memory;
pub mod metrics;
pub mod operator;
pub mod passkey;
pub mod prelude;
pub mod purge;
pub mod rate_limit;
pub mod reauth;
pub mod recovery;
mod recovery_cooldown;
mod redeem;
pub mod session;
pub mod signup;
pub mod storage;
mod sync;
pub mod token;
mod user;
pub mod verification;

pub use error::*;
