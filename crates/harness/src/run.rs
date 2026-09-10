//! The per-run key, derived in ONE place.
//!
//! **The attempt number is load-bearing, not decoration.** GitHub's `run_id` is
//! STABLE across "Re-run failed jobs"; only `run_attempt` changes. A project id
//! keyed on the run id alone would let attempt 2 inherit every row attempt 1
//! wrote — and attempt 2's C-04 then finds a task it is asserting cannot exist,
//! or its C-11 reads a record a previous attempt left behind. The failure is a
//! red run that describes the previous attempt rather than the system.
//!
//! ONE helper, called by every job that needs the key. The annex job (stage 3)
//! mints an ephemeral user under the same key, and two derivations of the same
//! string are two things that can disagree — which, for this string, means the
//! job that mints the identity and the job that uses it name different users.

/// The per-run project id sent as `X-Yadgar-Project`.
///
/// Task rows are scoped by project, so a failed run's rows are invisible to the
/// next run **and to the next attempt of the same run**. No cleanup is required
/// for correctness, and `find_tasks` assertions are self-scoped for free.
///
/// Off a runner the key falls back to `local-<pid>`, which is a different
/// namespace again — a workstation run must not be able to see or disturb a CI
/// run's rows, and vice versa.
pub fn project_id() -> String {
    format!("estate/{}", run_key())
}

/// The `<run-id>-<run-attempt>` half, or a local substitute.
///
/// Reads the ambient environment and hands it to [`run_key_from`], which holds
/// the whole of the decision. The split is what makes the decision testable:
/// see the note above the tests.
pub fn run_key() -> String {
    let id = std::env::var("GITHUB_RUN_ID").ok();
    let attempt = std::env::var("GITHUB_RUN_ATTEMPT").ok();
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
    fn the_project_id_is_namespaced_and_carries_the_key() {
        let p = project_id();
        assert!(p.starts_with("estate/"), "{p}");
        assert!(p.len() > "estate/".len(), "the key must not be empty");
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
