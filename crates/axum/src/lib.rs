// A panic aborts the host's whole process; returning an error leaves that decision to the host.
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod browser;
pub mod config;
mod cookies;
mod csrf;
mod dpop;
pub mod dto;
pub mod error;
pub mod extractors;
pub mod prelude;
mod purge;
mod routes;
pub mod session;
mod session_token;
mod state;

mod builder;

pub use doorman_core as core;
pub use doorman_core::client_ip::ClientIp;

pub use builder::{AuthServiceBuilder, BuilderError};
pub use config::{CookieConfig, CookieConfigBuilder, CookieConfigError, SameSite};
pub use error::{ErrorBody, ErrorPayload, ErrorResponse};
pub use extractors::{AuthSession, AuthUser, OptionalAuthUser, RequestContext};
pub use purge::{PurgeIntervalError, PurgeSchedule};
pub use session::{AuthContext, SessionLayer};
pub use state::AuthState;

use axum::Router;

use doorman_core::assembly::AuthCore;

pub struct AuthService {
    state: AuthState,
    session_layer: SessionLayer,
}

impl AuthService {
    pub fn builder(core: AuthCore, purge: PurgeSchedule) -> AuthServiceBuilder {
        AuthServiceBuilder::new(core, purge)
    }

    pub fn router(&self) -> Router {
        // The routes carry the layer themselves, so they stay checked however the host wires them.
        Router::new()
            .nest("/auth", routes::router(self.state.clone()))
            .route_layer(self.session_layer())
    }

    pub fn session_layer(&self) -> SessionLayer {
        self.session_layer.clone()
    }

    pub fn state(&self) -> &AuthState {
        &self.state
    }
}
