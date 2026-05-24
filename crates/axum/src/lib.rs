//! Axum HTTP integration for the `bauth` authentication library.
//!
//! This crate will host the mountable `Router`, session-loading middleware,
//! and `AuthUser` / `OptionalAuthUser` extractors that thin-wrap the
//! framework-agnostic primitives in [`bauth_core`]. For Milestone 1 it is a
//! publish-ready placeholder that re-exports the core crate so downstream
//! callers can already pull both crates from a single import surface.

pub use bauth_core as core;
