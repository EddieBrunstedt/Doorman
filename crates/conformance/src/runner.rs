use std::future::Future;
use std::pin::Pin;

// One worker would run each racer to completion before the next, so a store
// whose operations never await could never be raced.
const MIN_WORKERS: usize = 2;

pub(crate) type CheckFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct Check<S> {
    pub(crate) name: &'static str,
    pub(crate) run: fn(S) -> CheckFuture,
}

// Names each check after its function, so a report can't name a check
// differently from the code that failed.
macro_rules! checks {
    ($($check:ident),* $(,)?) => {
        &[$(
            $crate::runner::Check {
                name: stringify!($check),
                run: |stores| Box::pin(async move { $check(&stores).await }),
            },
        )*]
    };
}
pub(crate) use checks;

#[derive(Debug)]
pub(crate) struct Report {
    ran: usize,
    failures: Vec<Failure>,
}

#[derive(Debug, PartialEq)]
struct Failure {
    check: &'static str,
    message: String,
}

// Runs each check in its own task, in order, so a failing check reports and
// the next one still runs.
pub(crate) async fn run<S: Clone + Send + 'static>(stores: &S, checks: &[Check<S>]) -> Report {
    let workers = tokio::runtime::Handle::current().metrics().num_workers();
    assert!(
        workers >= MIN_WORKERS,
        "the conformance suite races concurrent callers and needs at least \
         {MIN_WORKERS} runtime workers, got {workers}; run it under \
         #[tokio::test(flavor = \"multi_thread\", worker_threads = 4)]",
    );

    let mut report = Report {
        ran: 0,
        failures: Vec::new(),
    };
    for check in checks {
        report.ran += 1;
        if let Err(err) = tokio::spawn((check.run)(stores.clone())).await {
            let message = if err.is_panic() {
                let payload = err.into_panic();
                payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panicked".to_string())
            } else {
                err.to_string()
            };
            report.failures.push(Failure {
                check: check.name,
                message,
            });
        }
    }
    report
}

impl Report {
    pub(crate) fn merge(mut self, other: Report) -> Report {
        self.ran += other.ran;
        self.failures.extend(other.failures);
        self
    }

    pub(crate) fn assert_passed(self) {
        if !self.failures.is_empty() {
            let failures: Vec<String> = self
                .failures
                .iter()
                .map(|f| format!("- {}: {}", f.check, f.message.replace('\n', "\n    ")))
                .collect();
            panic!(
                "{} of {} conformance checks failed:\n{}",
                self.failures.len(),
                self.ran,
                failures.join("\n"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn passes(_: &()) {}

    async fn panics_with_a_string(_: &()) {
        panic!("{} went wrong", "a string");
    }

    async fn panics_with_a_str(_: &()) {
        panic!("a str went wrong");
    }

    async fn panics_with_another_payload(_: &()) {
        std::panic::panic_any(7_u8);
    }

    async fn panics_over_two_lines(_: &()) {
        panic!("first line\nsecond line");
    }

    fn failure(check: &'static str, message: &str) -> Failure {
        Failure {
            check,
            message: message.to_string(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_check_runs_and_every_failure_is_kept_in_order() {
        let report = run(
            &(),
            checks![
                panics_with_a_string,
                passes,
                panics_with_a_str,
                panics_with_another_payload,
                passes,
            ],
        )
        .await;

        assert_eq!(report.ran, 5);
        assert_eq!(
            report.failures,
            [
                failure("panics_with_a_string", "a string went wrong"),
                failure("panics_with_a_str", "a str went wrong"),
                failure("panics_with_another_payload", "panicked"),
            ],
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_suite_that_only_passes_reports_nothing() {
        let report = run(&(), checks![passes, passes]).await;

        assert_eq!(report.ran, 2);
        assert!(report.failures.is_empty(), "{report:?}");
        report.assert_passed();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn merged_reports_count_both_suites() {
        let first = run(&(), checks![panics_with_a_str, passes]).await;
        let second = run(&(), checks![passes, panics_with_a_string]).await;

        let merged = first.merge(second);

        assert_eq!(merged.ran, 4);
        assert_eq!(
            merged.failures,
            [
                failure("panics_with_a_str", "a str went wrong"),
                failure("panics_with_a_string", "a string went wrong"),
            ],
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic(expected = "2 of 3 conformance checks failed:\n\
                               - panics_over_two_lines: first line\n    second line\n\
                               - panics_with_a_str: a str went wrong")]
    async fn a_failed_suite_panics_with_every_failure_after_the_count() {
        run(
            &(),
            checks![panics_over_two_lines, passes, panics_with_a_str],
        )
        .await
        .assert_passed();
    }
}
