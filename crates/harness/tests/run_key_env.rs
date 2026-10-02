//! Which environment variable feeds which half of the run key (ledger 846).
//!
//! `run.rs` tests `run_key_from` over literal arguments, which pins the
//! decision but not the WIRING: swapping `GITHUB_RUN_ID` and
//! `GITHUB_RUN_ATTEMPT` inside `run_key()` passed every one of those tests
//! (measured 2026-10-02). This test reads the key through `run_key()` itself,
//! with the two variables set to values that cannot be confused.
//!
//! WHY THIS IS ITS OWN TEST BINARY, AND WHY IT HOLDS EXACTLY ONE TEST. Setting
//! a process environment variable races with every other thread that reads
//! the environment, and libtest runs a binary's tests on parallel threads. Each
//! file under `tests/` is a separate process and cargo runs test binaries one
//! after another, so the only reader this mutation can race with is a second
//! test added to THIS file. Do not add one; put it in another file.
//!
//! The values are set unconditionally rather than only when absent. On a
//! runner GitHub sets both variables already, and a test that deferred to them
//! would assert the runner's own ordering — which is the thing under test.

use estate_harness::run::{project_id, run_key};

#[test]
fn run_key_reads_the_run_id_first_and_the_attempt_second() {
    std::env::set_var("GITHUB_RUN_ID", "1658821493");
    std::env::set_var("GITHUB_RUN_ATTEMPT", "3");

    assert_eq!(run_key(), "1658821493-3");
    assert_eq!(project_id(), "estate/1658821493-3");
}
