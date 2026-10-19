use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::assembly::AssemblyError;
use crate::audit::{Actor, AuditDispatch, AuditEventKind};
use crate::clock::Clock;
use crate::error::{Error, Result};
use crate::recovery_cool_down::RecoveryCoolDown;
use crate::session::{IssuedSession, ResolvedSession, SessionConfig, SessionContext, hash_token};
use crate::storage::{Session, SessionId, SessionStore, SessionSummary, StoredPasskey, UserId};
use crate::token::generate_token;

// Only `SessionRecords::reread` builds one, so whatever takes it acts for a session that was still
// live when the call reached core, not one revoked or expired since it was resolved.
#[derive(Debug)]
pub(crate) struct LiveSession(ResolvedSession);

impl Deref for LiveSession {
    type Target = ResolvedSession;

    fn deref(&self) -> &ResolvedSession {
        &self.0
    }
}

#[derive(Clone)]
pub(crate) struct SessionRecords {
    sessions: Arc<dyn SessionStore>,
    clock: Arc<dyn Clock>,
    audit: AuditDispatch,
    config: SessionConfig,
}

impl SessionRecords {
    pub(crate) fn new(
        sessions: Arc<dyn SessionStore>,
        clock: Arc<dyn Clock>,
        audit: AuditDispatch,
        config: SessionConfig,
    ) -> std::result::Result<Self, AssemblyError> {
        if let Some(idle_timeout) = config.idle_timeout
            && config.slide_interval >= idle_timeout
        {
            return Err(AssemblyError::IdleTimeoutInvalid {
                idle_timeout,
                reason: "must be strictly greater than the slide interval so an active session slides before it idles out",
            });
        }
        Ok(Self {
            sessions,
            clock,
            audit,
            config,
        })
    }

    #[tracing::instrument(
        skip_all,
        fields(session_id = tracing::field::Empty, user_id = tracing::field::Empty),
    )]
    pub(crate) async fn resolve(&self, token: &str) -> Result<Option<ResolvedSession>> {
        let stored = self
            .sessions
            .find_session_by_token_hash(&hash_token(token))
            .await?;
        let now = self.clock.now();
        let Some(session) = live(stored, now) else {
            return Ok(None);
        };
        let session = self.slide(session, now).await;
        Ok(Some(ResolvedSession::new(session, now)))
    }

    // Only `UserRecords::issue_session` calls this: it checks the user once the row is written,
    // and hands the token out only if that check passes.
    pub(crate) async fn create(
        &self,
        passkey: &StoredPasskey,
        context: &SessionContext,
    ) -> Result<IssuedSession> {
        let user_id = passkey.user_id;
        let now = self.clock.now();
        let cool_down = RecoveryCoolDown::of_passkey(passkey, now);
        if let Some(max) = self.config.max_sessions_per_user {
            self.enforce_session_cap(user_id, max.get(), cool_down, now)
                .await?;
        }

        let (token, token_hash) = generate_token()?;

        let session = Session {
            id: SessionId::new(),
            user_id,
            token_hash,
            created_at: now,
            last_used_at: now,
            expires_at: self.deadline(now, now),
            ip: context.ip.clone(),
            user_agent: context.user_agent.clone(),
            recovery_cool_down_until: cool_down.until(),
        };

        self.sessions.create_session(session.clone()).await?;
        Ok(IssuedSession {
            session: ResolvedSession::new(session, now),
            token,
            absolute_lifetime: self.config.absolute_lifetime,
        })
    }

    pub(crate) async fn discard(&self, session: &ResolvedSession) {
        if let Err(error) = self.sessions.delete_session(session.id).await {
            tracing::warn!(
                session_id = %session.id,
                %error,
                "refused session left behind; its token was never handed out",
            );
        }
    }

    async fn enforce_session_cap(
        &self,
        user_id: UserId,
        max: u32,
        cool_down: RecoveryCoolDown,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let active = self.list_summaries_for_user(user_id).await?;
        let max = max as usize;
        if active.len() < max {
            return Ok(());
        }
        let evict = active.len() + 1 - max;
        // Short of evictable sessions, the user goes over the cap rather than lose one outside
        // cool-down; the next session outside it evicts down to the cap again.
        let mut evictable = cool_down.evictable_by(active, now);
        evictable.sort_by_key(|s| s.created_at);
        for session in evictable.into_iter().take(evict) {
            self.revoke_session(&session, Actor::of_session(&session))
                .await?;
        }
        Ok(())
    }

    fn deadline(&self, created_at: DateTime<Utc>, last_used: DateTime<Utc>) -> DateTime<Utc> {
        let after = |start: DateTime<Utc>, span: Duration| {
            chrono::Duration::from_std(span)
                .ok()
                .and_then(|span| start.checked_add_signed(span))
                .unwrap_or(DateTime::<Utc>::MAX_UTC)
        };
        let absolute = after(created_at, self.config.absolute_lifetime);
        match self.config.idle_timeout {
            Some(idle) => absolute.min(after(last_used, idle)),
            None => absolute,
        }
    }

    // Every write made for a session reads it again, so one revoked or expired since it was
    // resolved writes nothing. Logging out needs no re-read: it only deletes the session.
    pub(crate) async fn reread(&self, session: &ResolvedSession) -> Result<LiveSession> {
        let stored = self
            .sessions
            .find_session_by_id(session.id)
            .await?
            .filter(|stored| stored.token_hash == *session.token_hash());
        let now = self.clock.now();
        let stored = live(stored, now).ok_or(Error::SessionNotFound)?;
        Ok(LiveSession(ResolvedSession::new(stored, now)))
    }

    fn slide_due(&self, session: &Session, now: DateTime<Utc>) -> bool {
        self.config.idle_timeout.is_some()
            && (now - session.last_used_at)
                .to_std()
                .is_ok_and(|since_used| since_used >= self.config.slide_interval)
    }

    async fn slide(&self, session: Session, now: DateTime<Utc>) -> Session {
        if !self.slide_due(&session, now) {
            return session;
        }

        let mut updated = session.clone();
        updated.last_used_at = now;
        updated.expires_at = self.deadline(session.created_at, now);
        match self
            .sessions
            .touch_session(updated.id, updated.last_used_at, updated.expires_at)
            .await
        {
            Ok(()) => {
                tracing::debug!(session_id = %updated.id, "session deadline slid");
                updated
            }
            Err(error) => {
                tracing::warn!(
                    session_id = %session.id,
                    %error,
                    "session touch failed; serving un-slid session",
                );
                session
            }
        }
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub(crate) async fn revoke_all_for_user(&self, user_id: UserId) -> Result<u64> {
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, None)
            .await?;
        tracing::info!(count, outcome = "revoked_all", "user sessions revoked");
        Ok(count)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    async fn list_for_user(&self, user_id: UserId) -> Result<Vec<Session>> {
        let now = self.clock.now();
        let mut sessions = self.sessions.list_for_user(user_id).await?;
        sessions.retain(|session| session.expires_at > now);
        Ok(sessions)
    }

    #[tracing::instrument(skip(self), fields(user_id = %user_id))]
    pub(crate) async fn list_summaries_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<SessionSummary>> {
        let sessions = self.list_for_user(user_id).await?;
        Ok(sessions.iter().map(SessionSummary::from).collect())
    }

    pub(crate) async fn revoke_others(&self, keep: &SessionSummary, actor: Actor) -> Result<u64> {
        let user_id = keep.user_id;
        let count = self
            .sessions
            .delete_sessions_for_user(user_id, Some(keep.id))
            .await?;
        tracing::info!(
            count,
            outcome = "revoked_others",
            "other user sessions revoked"
        );
        self.audit
            .emit(
                actor,
                AuditEventKind::OtherSessionsRevoked {
                    user_id,
                    revoked_count: count,
                },
            )
            .await;
        Ok(count)
    }

    pub(crate) async fn log_out(&self, session: &ResolvedSession) -> Result<()> {
        self.revoke_owned(session.user_id, session.id, Actor::of_session(session))
            .await
    }

    pub(crate) async fn revoke_owned(
        &self,
        target_user_id: UserId,
        session_id: SessionId,
        actor: Actor,
    ) -> Result<()> {
        let Some(session) = self.sessions.find_session_by_id(session_id).await? else {
            tracing::warn!(outcome = "not_found", "session revoke failed");
            return Err(Error::SessionNotFound);
        };
        if session.user_id != target_user_id {
            tracing::warn!(outcome = "not_owned", "session revoke failed");
            return Err(Error::SessionNotFound);
        }
        self.revoke_session(&SessionSummary::from(session), actor)
            .await
    }

    async fn revoke_session(&self, session: &SessionSummary, actor: Actor) -> Result<()> {
        self.sessions.delete_session(session.id).await?;
        self.audit
            .emit(
                actor,
                AuditEventKind::SessionRevoked {
                    user_id: session.user_id,
                    session_id: session.id,
                },
            )
            .await;
        Ok(())
    }
}

// An expired row reads like a missing one, so the answer doesn't depend on whether the store has
// dropped it yet.
fn live(stored: Option<Session>, now: DateTime<Utc>) -> Option<Session> {
    let Some(session) = stored else {
        tracing::warn!(outcome = "not_found", "session validate failed");
        return None;
    };
    let span = tracing::Span::current();
    span.record("user_id", tracing::field::display(session.user_id));
    span.record("session_id", tracing::field::display(session.id));
    if session.expires_at <= now {
        tracing::warn!(outcome = "expired", "session validate failed");
        return None;
    }
    Some(session)
}
