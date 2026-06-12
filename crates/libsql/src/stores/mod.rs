//! The five `doorman-core` store implementations backed by a libSQL connection.
//!
//! Each submodule holds one store. The SQL is SQLite's dialect (libSQL speaks
//! it verbatim), mirroring the doorman-sqlx SQLite adapter: ids and hashes are
//! BLOBs, timestamps are RFC3339 TEXT, and the atomic single-use `take` /
//! `consume` paths are a single `DELETE ... RETURNING` — which libSQL supports,
//! so no transaction is needed.

pub(crate) mod passkey_chal;
pub(crate) mod passkey_cred;
pub(crate) mod session;
pub(crate) mod user;
pub(crate) mod verification;
