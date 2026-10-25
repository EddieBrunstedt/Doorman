// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

pub mod config;
mod cookies;
mod csrf;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod prelude;
mod routes;
pub mod session;
mod state;

mod builder;

pub use doorman_core as core;

pub use builder::{AuthServiceBuilder, BuilderError};
pub use config::CookieConfig;
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, ClientIp, OptionalAuthUser, RequestContext};
pub use session::{AuthContext, SessionLayer};
pub use state::AuthState;

use axum::Router;

use doorman_core::assembly::AuthCore;

pub struct AuthService {
    state: AuthState,
    session_layer: SessionLayer,
}

impl AuthService {
    pub fn builder(core: AuthCore) -> AuthServiceBuilder {
        AuthServiceBuilder::new(core)
    }

    pub fn router(&self) -> Router {
        Router::new().nest("/auth", routes::router(self.state.clone()))
    }

    pub fn session_layer(&self) -> SessionLayer {
        self.session_layer.clone()
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }
}
