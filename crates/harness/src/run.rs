//! The run's project claim, and the per-run key, each derived in ONE place.
//!
//! **THE CLAIM IS ONE FIXED REGISTERED PATH, `estate/smoke`, ON EVERY RUN
//! (ledger 1244, ruling B, 2026-10-18).** It used to be
//! `estate/<run-id>-<attempt>`, one project per run. The gateway resolves a
//! claim by ANCESTOR against its project registry, and a per-run path can never
//! be registered — the seeder is the registry's one writer (ADR-0705/0713), and
//! nothing may mint a row at run time. So a per-run claim resolved to the
//! single-segment `estate` root, which ADR-0673 makes a namespace anchor: under
//! enforcement that is `PROJECT_UNREGISTERED_ORG`, and every row past C-03
//! would be refused. `estate/smoke` is the path seeder#1 declares under that
//! root. **CO-CHANGE: the seeder's declaration and the literal below must name
//! the same path**, or every run claims an unregistered project again.
//!
//! **PER-RUN PROJECT ISOLATION IS GIVEN UP DELIBERATELY.** Every run, every
//! attempt of a run and every workstation run now share one namespace and one
//! task counter. Nothing in the rows relies on the namespace being empty any
//! more: a row finds its own task by the id it was handed, and its titles carry
//! [`title_marker`], so a run tells its rows from every other run's by title.
//!
//! **The attempt number is still load-bearing, now for titles.** GitHub's
//! `run_id` is STABLE across "Re-run failed jobs"; only `run_attempt` changes.
//! A marker keyed on the run id alone would give attempt 2 the same titles as
//! attempt 1, and a row whose read-back returned attempt 1's task would read as
//! its own.
//!
//! ONE helper for each, called by every job that needs it. Two derivations of
//! the same string are two things that can disagree.

/// The project id sent as `X-Yadgar-Project`: the one registered path.
///
/// Not configuration in ADR-0569's sense: it is not a knob with a default an
/// operator could not see, but the identity the registry's seed declaration
/// gives this repository, and it changes only together with that declaration.
pub fn project_id() -> String {
    "estate/smoke".to_string()
}

/// A run-unique marker for task titles: the run key, then the process start.
///
/// On a runner the run key alone is unique. Off a runner it is `local-<pid>`,
/// and a pid is recycled across workstation sessions — harmless while each run
/// had its own project, but in the shared project a recycled title would let a
/// row's by-number read-back match some earlier run's task. The nanoseconds at
/// first use close that. Computed once per process, so every row in one test
/// binary carries the same marker and one `grep` finds a run's rows.
///
/// The clock is not configuration either: it is read, never chosen.
pub fn title_marker() -> String {
    static MARKER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    MARKER
        .get_or_init(|| {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            format!("{}-{nanos}", run_key())
        })
        .clone()
}

/// The `<run-id>-<run-attempt>` key that leads [`title_marker`], or a local
/// substitute.
///
/// Reads the ambient environment and hands it to [`run_key_from`], which holds
/// the whole of the decision. The split is what makes the decision testable:
/// see the note above the tests.
///
/// **ADR-0569-EXCEPTION(ABS) — THIS IS NOT CONFIGURATION.** `GITHUB_RUN_ID`
/// and `GITHUB_RUN_ATTEMPT` are GitHub's own ambient variables, not a knob
/// this crate exposes to an operator; there is no seed value for them to have
/// ONE source in. Absence off a runner is the ordinary case this function
/// exists to detect, not a misconfiguration to refuse over, and
/// `run_key_from`'s `local-<pid>` fallback is a title key nobody chooses
/// or configures — exactly the "value that is not configuration at all"
/// ADR-0569's own consequences call out.
pub fn run_key() -> String {
    let id = std::env::var("GITHUB_RUN_ID").ok(); // ADR-0569-EXCEPTION(ABS): absent means off-runner, not a misconfigured knob.
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").ok(); // ADR-0569-EXCEPTION(ABS): absent means off-runner; the local-<pid> fallback is a title key, not a default.
    run_key_from(id.as_deref(), attempt.as_deref())
}

/// The decision itself, over values rather than over the process environment.
///
/// `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` are default variables GitHub sets
/// on every runner, so a test that reads the ambient environment can only ever
/// see ONE of the two branches below — whichever one the machine it runs on
/// happens to be. Taking the pair as arguments is what lets both branches be
/// asserted everywhere, on a workstation and on a runner alike.
fn run_key_from(id: Option<&str>, attempt: Option<&str>) -> String {
    match (id, attempt) {
        (Some(id), Some(attempt)) if !id.is_empty() && !attempt.is_empty() => {
            format!("{id}-{attempt}")
        }
        // A run id with no attempt is not treated as attempt 1. It means the
        // environment is not the one this key was designed for, and guessing
        // would reintroduce exactly the collision the attempt number prevents.
        _ => format!("local-{}", std::process::id()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that matters is the SHAPE, and it can be asserted without
    /// touching the process environment — which two tests running in parallel
    /// would race on.
    #[test]
    fn the_project_id_is_the_one_registered_path_and_carries_no_run_key() {
        assert_eq!(project_id(), "estate/smoke");
        assert!(
            !project_id().contains(&run_key()),
            "the run key must not reach the claim"
        );
    }

    /// The marker leads with the run key, so a row's title names the run that
    /// wrote it, and carries a second part so a recycled pid cannot repeat it.
    #[test]
    fn the_title_marker_leads_with_the_run_key_and_adds_a_per_process_part() {
        let m = title_marker();
        let key = run_key();
        assert!(m.starts_with(&format!("{key}-")), "{m}");
        assert!(
            m.len() > key.len() + 1,
            "the per-process part must not be empty: {m}"
        );
        assert_eq!(m, title_marker(), "one process, one marker");
    }

    /// Off a runner the key is local and per-process, so a workstation run
    /// cannot collide with anything.
    ///
    /// The absent runner is passed in rather than read from the environment.
    /// The earlier form of this test skipped itself when `GITHUB_RUN_ID` was
    /// set, which on a runner is always — so it reported `ok` in CI having
    /// asserted nothing.
    #[test]
    fn off_a_runner_the_key_is_local() {
        assert_eq!(
            run_key_from(None, None),
            format!("local-{}", std::process::id())
        );
    }

    /// On a runner the key is the run id and the attempt, in that order and
    /// joined by a hyphen. The attempt is what makes a re-run a new namespace.
    #[test]
    fn on_a_runner_the_key_carries_the_run_id_and_the_attempt() {
        assert_eq!(run_key_from(Some("1658821493"), Some("3")), "1658821493-3");
    }

    /// A run id with no attempt is the environment the key was NOT designed
    /// for, and it falls back rather than guessing attempt 1. An empty value is
    /// the same case: GitHub sets both variables together, so one of them
    /// arriving blank is not a runner either.
    #[test]
    fn a_run_id_without_an_attempt_is_not_attempt_one() {
        let local = format!("local-{}", std::process::id());
        assert_eq!(run_key_from(Some("1658821493"), None), local);
        assert_eq!(run_key_from(Some("1658821493"), Some("")), local);
        assert_eq!(run_key_from(Some(""), Some("3")), local);
    }
}
