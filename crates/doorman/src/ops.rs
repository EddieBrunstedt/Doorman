use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::core::clock::Clock;
use crate::core::error::StorageResult;
use crate::core::purge::PurgeSummary;
use crate::core::storage::ExpiringStores;

pub async fn run_purge(stores: ExpiringStores) -> ExitCode {
    match execute(stores, std::env::args().skip(1)).await {
        Ok((options, summary)) => {
            print!("{}", render(options.now, options.json, &summary));
            for (store, error) in summary.failures() {
                eprintln!("doorman purge: sweeping {store} failed: {error}");
            }
            exit_code(&summary)
        }
        Err(message) => {
            eprintln!("doorman purge: {message}");
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
            let summary = stores.purge_all_expired(clock.now()).await;
            for (store, error) in summary.failures() {
                tracing::warn!(store, %error, "background purge sweep failed");
            }
            tracing::debug!(
                sessions = summary.sessions.as_ref().ok(),
                email_links = summary.email_links.as_ref().ok(),
                passkey_challenges = summary.passkey_challenges.as_ref().ok(),
                total = summary.total(),
                "purged expired rows",
            );
        }
    })
}

struct Options {
    now: DateTime<Utc>,
    json: bool,
}

async fn execute(
    stores: ExpiringStores,
    args: impl IntoIterator<Item = String>,
) -> Result<(Options, PurgeSummary), String> {
    let options = parse_args(args)?;
    let summary = stores.purge_all_expired(options.now).await;
    Ok((options, summary))
}

fn exit_code(summary: &PurgeSummary) -> ExitCode {
    if summary.failures().next().is_none() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut now: Option<DateTime<Utc>> = None;
    let mut json = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--json" {
            json = true;
        } else if arg == "--now" {
            let value = args
                .next()
                .ok_or_else(|| "--now requires an RFC 3339 timestamp argument".to_string())?;
            now = Some(parse_now(&value)?);
        } else if let Some(value) = arg.strip_prefix("--now=") {
            now = Some(parse_now(value)?);
        } else {
            return Err(format!(
                "unrecognized argument `{arg}` (supported: --now <rfc3339>, --json)"
            ));
        }
    }

    Ok(Options {
        now: now.unwrap_or_else(Utc::now),
        json,
    })
}

fn parse_now(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| {
            format!("could not parse --now `{value}` as an RFC 3339 timestamp: {error}")
        })
}

fn render(now: DateTime<Utc>, json: bool, summary: &PurgeSummary) -> String {
    let now = now.to_rfc3339();

    if json {
        // A failed store is `null`; its error goes to stderr, so no error text needs escaping here.
        let counts: String = summary
            .outcomes()
            .map(|(store, outcome)| format!(",\"{store}\":{}", json_count(outcome)))
            .collect();
        return format!(
            "{{\"now\":\"{now}\"{counts},\"total\":{}}}\n",
            summary.total()
        );
    }

    let mut out = format!("doorman purge: swept expired rows as of {now}\n");
    for (store, outcome) in summary.outcomes() {
        let count = match outcome {
            Ok(count) => count.to_string(),
            Err(_) => "failed".to_string(),
        };
        out.push_str(&format!("  {store:<18} = {count}\n"));
    }
    out.push_str(&format!("  {:<18} = {}\n", "total", summary.total()));
    if summary.total() == 0 && summary.failures().next().is_none() {
        out.push_str(
            "  note: nothing matched — if you expected rows, confirm this process targets the \
             same backend and namespace as the running app\n",
        );
    }
    out
}

fn json_count(outcome: &StorageResult<u64>) -> String {
    match outcome {
        Ok(count) => count.to_string(),
        Err(_) => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::StorageError;
    use crate::core::memory::InMemoryStorage;
    use crate::core::storage::{Session, SessionId, SessionTransport, TokenHash, UserId};
    use doorman_test_support::MockClock;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    async fn seed_sessions(stores: &ExpiringStores, user_id: UserId, now: DateTime<Utc>) {
        let mk_session = |tag: u8, expires_at: DateTime<Utc>| Session {
            id: SessionId::new(),
            user_id,
            token_hash: TokenHash([tag; 32]),
            transport: SessionTransport::Cookie,
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
        assert!(parse_args(args(&["--bogus"])).is_err());
    }

    #[test]
    fn parse_args_rejects_now_without_a_value() {
        assert!(parse_args(args(&["--now"])).is_err());
    }

    #[test]
    fn parse_args_rejects_an_unparseable_now() {
        assert!(parse_args(args(&["--now", "not-a-timestamp"])).is_err());
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
        assert_eq!(summary.sessions.as_ref().expect("sessions"), &1);
        assert_eq!(summary.total(), 1);
    }

    #[tokio::test]
    async fn execute_surfaces_a_flag_error() {
        let stores = InMemoryStorage::new().expiring();
        assert!(execute(stores, args(&["--when", "now"])).await.is_err());
    }

    fn summary_with_failed_email_links() -> PurgeSummary {
        PurgeSummary {
            sessions: Ok(2),
            email_links: Err(StorageError::msg("email link store unavailable")),
            passkey_challenges: Ok(0),
        }
    }

    fn at() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_000_000, 0).expect("timestamp")
    }

    #[test]
    fn a_failed_store_fails_the_run() {
        assert_eq!(
            exit_code(&summary_with_failed_email_links()),
            ExitCode::FAILURE
        );
        let complete = PurgeSummary {
            sessions: Ok(0),
            email_links: Ok(0),
            passkey_challenges: Ok(0),
        };
        assert_eq!(exit_code(&complete), ExitCode::SUCCESS);
    }

    #[test]
    fn json_reports_a_failed_store_as_null() {
        let line = render(at(), true, &summary_with_failed_email_links());
        assert_eq!(
            line,
            format!(
                "{{\"now\":\"{}\",\"sessions\":2,\"email_links\":null,\"passkey_challenges\":0,\"total\":2}}\n",
                at().to_rfc3339()
            )
        );
    }

    #[test]
    fn text_reports_a_failed_store_and_skips_the_nothing_matched_note() {
        let summary = PurgeSummary {
            sessions: Ok(0),
            email_links: Err(StorageError::msg("email link store unavailable")),
            passkey_challenges: Ok(0),
        };
        let text = render(at(), false, &summary);
        assert!(text.contains("  email_links        = failed\n"), "{text}");
        assert!(text.contains("  total              = 0\n"), "{text}");
        assert!(!text.contains("nothing matched"), "{text}");
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
