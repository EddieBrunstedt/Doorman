use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::core::clock::Clock;
use crate::core::error::StorageError;
use crate::core::purge::PurgeSummary;
use crate::core::storage::ExpiringStores;

pub async fn run_purge(stores: ExpiringStores) -> ExitCode {
    match execute(stores, std::env::args().skip(1)).await {
        Ok((options, summary)) => {
            print_summary(options.now, options.json, &summary);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("doorman purge: {err}");
            ExitCode::FAILURE
        }
    }
}

pub fn spawn_purge_task(
    stores: ExpiringStores,
    clock: Arc<dyn Clock>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let now = clock.now();
            match stores.purge_all_expired(now).await {
                Ok(summary) => {
                    tracing::debug!(
                        sessions = summary.sessions,
                        email_links = summary.email_links,
                        passkey_challenges = summary.passkey_challenges,
                        total = summary.total(),
                        "purged expired rows",
                    );
                }
                Err(error) => {
                    tracing::warn!(%error, "background purge sweep failed");
                }
            }
        }
    })
}

struct Options {
    now: DateTime<Utc>,
    json: bool,
}

#[derive(Debug)]
enum PurgeError {
    Args(String),
    Sweep(StorageError),
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeError::Args(message) => write!(f, "{message}"),
            PurgeError::Sweep(error) => write!(f, "sweep failed: {error}"),
        }
    }
}

async fn execute(
    stores: ExpiringStores,
    args: impl IntoIterator<Item = String>,
) -> Result<(Options, PurgeSummary), PurgeError> {
    let options = parse_args(args)?;
    let summary = stores
        .purge_all_expired(options.now)
        .await
        .map_err(PurgeError::Sweep)?;
    Ok((options, summary))
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, PurgeError> {
    let mut now: Option<DateTime<Utc>> = None;
    let mut json = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            json = true;
        } else if arg == "--now" {
            let value = args.next().ok_or_else(|| {
                PurgeError::Args("--now requires an RFC 3339 timestamp argument".to_string())
            })?;
            now = Some(parse_now(&value)?);
        } else if let Some(value) = arg.strip_prefix("--now=") {
            now = Some(parse_now(value)?);
        } else {
            return Err(PurgeError::Args(format!(
                "unrecognized argument `{arg}` (supported: --now <rfc3339>, --json)"
            )));
        }
    }

    Ok(Options {
        now: now.unwrap_or_else(Utc::now),
        json,
    })
}

fn parse_now(value: &str) -> Result<DateTime<Utc>, PurgeError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| {
            PurgeError::Args(format!(
                "could not parse --now `{value}` as an RFC 3339 timestamp: {error}"
            ))
        })
}

fn print_summary(now: DateTime<Utc>, json: bool, summary: &PurgeSummary) {
    let now = now.to_rfc3339();
    if json {
        println!(
            "{{\"now\":\"{now}\",\"sessions\":{},\"email_links\":{},\"passkey_challenges\":{},\"total\":{}}}",
            summary.sessions,
            summary.email_links,
            summary.passkey_challenges,
            summary.total(),
        );
        return;
    }

    println!("doorman purge: swept expired rows as of {now}");
    println!("  sessions            = {}", summary.sessions);
    println!("  email_links = {}", summary.email_links);
    println!("  passkey_challenges  = {}", summary.passkey_challenges);
    println!("  total               = {}", summary.total());
    if summary.total() == 0 {
        println!(
            "  note: nothing matched — if you expected rows, confirm this process targets the \
             same backend and namespace as the running app"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::memory::InMemoryStorage;
    use crate::core::storage::{Session, SessionId, TokenHash, UserId};
    use doorman_test_support::MockClock;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    async fn seed_sessions(stores: &ExpiringStores, user_id: UserId, now: DateTime<Utc>) {
        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            created_at: now - chrono::Duration::hours(2),
            last_used_at: now - chrono::Duration::hours(2),
            expires_at,
            ip: None,
            user_agent: None,
            recovery_cool_down_until: None,
        };
        stores
            .sessions
            .create_session(mk_session(1, now - chrono::Duration::hours(1)))
            .await
            .expect("expired session");
        stores
            .sessions
            .create_session(mk_session(2, now + chrono::Duration::hours(1)))
            .await
            .expect("live session");
    }

    #[test]
    fn parse_args_reads_both_flags() {
        let options =
            parse_args(args(&["--now", "2020-01-01T00:00:00Z", "--json"])).expect("flags parse");
        assert!(options.json);
        assert_eq!(
            options.now,
            DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn parse_args_accepts_the_equals_form() {
        let options =
            parse_args(args(&["--now=2020-01-01T00:00:00Z"])).expect("equals form parses");
        assert!(!options.json);
    }

    #[test]
    fn parse_args_defaults_now_and_json() {
        let before = Utc::now();
        let options = parse_args(args(&[])).expect("no flags is valid");
        assert!(!options.json);
        assert!(options.now >= before);
    }

    #[test]
    fn parse_args_rejects_unknown_flag() {
        assert!(matches!(
            parse_args(args(&["--bogus"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[test]
    fn parse_args_rejects_now_without_a_value() {
        assert!(matches!(
            parse_args(args(&["--now"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[test]
    fn parse_args_rejects_an_unparseable_now() {
        assert!(matches!(
            parse_args(args(&["--now", "not-a-timestamp"])),
            Err(PurgeError::Args(_))
        ));
    }

    #[tokio::test]
    async fn execute_sweeps_the_storage_and_reports_counts() {
        let now = DateTime::<Utc>::from_timestamp(1_000_000, 0).expect("timestamp");
        let stores = InMemoryStorage::new().expiring();
        seed_sessions(&stores, UserId::new(), now).await;

        let (options, summary) = execute(stores, args(&["--now", &now.to_rfc3339(), "--json"]))
            .await
            .expect("execute ok");

        assert!(options.json);
        assert_eq!(options.now, now);
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.total(), 1);
    }

    #[tokio::test]
    async fn execute_surfaces_a_flag_error() {
        let stores = InMemoryStorage::new().expiring();
        assert!(matches!(
            execute(stores, args(&["--when", "now"])).await,
            Err(PurgeError::Args(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn spawn_purge_task_sweeps_on_its_interval() {
        let now = DateTime::<Utc>::from_timestamp(2_000_000, 0).expect("timestamp");
        let user_id = UserId::new();
        let stores = InMemoryStorage::new().expiring();
        seed_sessions(&stores, user_id, now).await;

        let handle = spawn_purge_task(
            stores.clone(),
            Arc::new(MockClock::new(now)),
            Duration::from_secs(3600),
        );

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        handle.abort();

        let remaining = stores.sessions.list_for_user(user_id).await.expect("list");
        assert_eq!(remaining.len(), 1, "background task swept the expired row");
        assert!(remaining[0].expires_at > now);
    }
}
