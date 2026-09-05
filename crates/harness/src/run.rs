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
pub fn run_key() -> String {
    match (
        std::env::var("GITHUB_RUN_ID"),
        std::env::var("GITHUB_RUN_ATTEMPT"),
    ) {
        (Ok(id), Ok(attempt)) if !id.is_empty() && !attempt.is_empty() => {
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
    #[test]
    fn off_a_runner_the_key_is_local() {
        if std::env::var("GITHUB_RUN_ID").is_ok() {
            return;
        }
        assert!(run_key().starts_with("local-"), "{}", run_key());
    }
}
