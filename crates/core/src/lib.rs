// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

pub mod assembly;
mod assertion;
pub mod audit;
mod challenge;
pub mod client_ip;
pub mod clock;
mod context;
pub mod destructive;
pub mod dpop;
pub mod email;
pub mod email_link;
mod email_link_registration;
pub mod encoding;
pub mod error;
pub mod lifetime;
pub mod memory;
pub mod metrics;
pub mod operator;
pub mod passkey;
mod passkey_registration;
pub mod prelude;
pub mod purge;
pub mod rate_limit;
pub mod reauth;
pub mod recovery;
mod recovery_cool_down;
mod redeem;
pub mod relying_party;
pub mod security_notice;
pub mod session;
mod session_records;
pub mod signup;
pub mod storage;
mod sync;
pub mod token;
pub mod user;
mod user_records;

pub use error::*;
