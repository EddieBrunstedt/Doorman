use std::sync::Arc;

use doorman_core::assembly::AuthCore;

use url::Url;

use crate::AuthService;
use crate::config::CookieConfig;
use crate::csrf::TrustedOrigins;
use crate::purge::{PurgeSchedule, Sweeper};
use crate::session::{SessionLayer, SessionLayerState};
use crate::state::AuthState;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error(
        "PurgeSchedule::in_process sweeps on a tokio task, so the service must be built inside a tokio runtime"
    )]
    PurgeNeedsRuntime,
}

pub struct AuthServiceBuilder {
    core: AuthCore,
    cookie_config: Option<CookieConfig>,
    trusted_origins: Vec<Url>,
    purge: PurgeSchedule,
}

impl AuthServiceBuilder {
    pub(crate) fn new(core: AuthCore, purge: PurgeSchedule) -> Self {
        Self {
            core,
            cookie_config: None,
            trusted_origins: Vec::new(),
            purge,
        }
    }

    pub fn cookie(mut self, config: CookieConfig) -> Self {
        self.cookie_config = Some(config);
        self
    }

    pub fn trusted_origin(mut self, origin: Url) -> Self {
        self.trusted_origins.push(origin);
        self
    }

    pub fn build(self) -> Result<AuthService, BuilderError> {
        let sweeper = Sweeper::for_schedule(self.purge)?;
        let core = self.core;
        let cookie_config = self.cookie_config.unwrap_or_default();

        // The relying party's origins are where the application's pages run passkey ceremonies,
        // so they are the origins its requests come from.
        let trusted_origins = TrustedOrigins::new(
            core.passkey
                .relying_party()
                .origins()
                .iter()
                .cloned()
                .chain(self.trusted_origins),
        );

        let layer_state = Arc::new(SessionLayerState {
            sessions: core.sessions.clone(),
            cookie: cookie_config.clone(),
            trusted_origins,
        });

        let core = Arc::new(core);
        // Started last, so a build that fails leaves no task behind.
        if let Some(sweeper) = sweeper {
            sweeper.start(&core);
        }

        let state = AuthState {
            core,
            cookie_config: Arc::new(cookie_config),
        };

        Ok(AuthService {
            state,
            session_layer: SessionLayer::new(layer_state),
        })
    }
}
