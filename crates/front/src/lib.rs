//! Shared setup for the front-door contracts.
//!
//! The rows themselves live in `tests/`. What lives here is the small amount of
//! wiring every row needs — the reference values, a client that trusts one root,
//! and the two standing identities — so that a row's own text is the contract
//! and nothing else.
//!
//! **THE SUITE HOLDS NO BEARER TOKEN.** It holds a password, supplied by the
//! environment, and it starts every run with `POST /auth/login` — which is
//! contract C-01. Credential acquisition and the first contract are the same
//! call. What ADR-0492's ceremony is held to here is narrower than the ceremony
//! itself and is stated plainly in the repository README: no long-lived bearer
//! token is stored anywhere, and the credential the suite starts from was
//! redeemed through the same `POST /auth/enrol` a person uses.

use anyhow::{Context, Result};
use estate_harness::{auth, client::Edge, reference::Reference, run};

/// One suite identity: a name from `reference.toml`, a password from the
/// environment.
///
/// **THE NAME NO LONGER HAS A COMPILED-IN DEFAULT (ADR-0569, ledger 716).** It
/// used to: `DEFAULT_USERNAME = "estate-suite"` sat here behind an
/// `ESTATE_USERNAME` read, and NOTHING in this repository ever set that variable
/// — not `smoke.yaml`, not `scripts/enrol.sh`, not `MIGRATION_NOTES.md`. So the
/// effective value was a constant in source that no operator could see, edit or
/// override, which is precisely the state ADR-0569 exists to delete. It is a
/// declared line in `reference.toml` now, under `[identity]`, and the
/// environment read is gone rather than layered on top of the file: ADR-0571
/// rules that a knob lives in exactly one place and that precedence between two
/// sources is where drift hides.
///
/// The PASSWORD stays an environment read, and that is not an inconsistency. It
/// is a credential rather than a knob — it arrives from the `estate` GitHub
/// environment, it must never be committed, and it already refuses rather than
/// defaulting.
pub struct Identity {
    pub username: String,
    password: String,
}

impl Identity {
    /// The first standing identity, `S`.
    pub fn primary(reference: &Reference) -> Result<Self> {
        Self::named(&reference.identity.primary, "ESTATE_PASSWORD")
    }

    /// The second standing identity, `S2`, which the confinement rows need.
    pub fn secondary(reference: &Reference) -> Result<Self> {
        Self::named(&reference.identity.secondary, "ESTATE_PASSWORD_2")
    }

    /// Absence is an ERROR, never a skip.
    ///
    /// A suite that skipped when a credential was missing would report green
    /// having exercised nothing, which is the failure mode this whole repository
    /// exists to remove one level up. The message names the ceremony that
    /// supplies the value, so a red run says "the credential is missing" rather
    /// than "the contract is broken".
    fn named(username: &str, pass_var: &str) -> Result<Self> {
        let password = std::env::var(pass_var).with_context(|| {
            format!(
                "{pass_var} is not set, so this row cannot authenticate. It is supplied by the \
                 `estate` GitHub environment, written once by the identity ceremony in \
                 scripts/enrol.sh. This is a MISSING CREDENTIAL, not a failing contract."
            )
        })?;
        Ok(Self {
            username: username.to_string(),
            password,
        })
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Everything a row needs to reach the edge.
pub struct Suite {
    pub reference: Reference,
    pub edge: Edge,
    /// `X-Yadgar-Project`: `estate/smoke`, the same registered path on every
    /// run (ledger 1244). It isolates NOTHING between runs; see `marker`.
    pub project: String,
    /// What makes this run's task titles its own, in the shared project:
    /// `<run-id>-<run-attempt>-<nanos>`, or `local-<pid>-<nanos>` off a runner.
    pub marker: String,
}

impl Suite {
    pub fn open() -> Result<Self> {
        let reference = Reference::load()?;
        let edge = Edge::trusting_committed_root(&reference)?;
        Ok(Self {
            reference,
            edge,
            project: run::project_id(),
            marker: run::title_marker(),
        })
    }

    /// Log in and return a bearer token, or explain what answered instead.
    pub async fn token_for(&self, identity: &Identity) -> Result<String> {
        let capture = auth::login(&self.edge, &identity.username, identity.password()).await?;
        anyhow::ensure!(
            capture.status == 200,
            "login for {} answered {} — {}",
            identity.username,
            capture.status,
            capture.body_str()
        );
        auth::token_of(&capture)
    }
}

/// The page size a listing row asks for. Sixteen is the most ids that can sort
/// between [`listing_token`] and the id it looks for: they share every
/// character but the last, and the last is one hex digit. A larger value would
/// only let the page grow with other runs' tasks.
pub const LISTING_PAGE_SIZE: u32 = 16;

/// The `page_token` that starts a listing page just BELOW `id`: the id with its
/// last character cut off.
///
/// **WHY A DERIVED TOKEN, AND NOT A WALK (yaadgaar 269).** task-db lists in
/// `ORDER BY id` with `id > token` (`task-db/src/read.rs`, keyset paging), and
/// the project is shared by every run, so a task created now is on the LAST
/// page. The row used to read every page from the first, and its cost grew by
/// the two tasks each run leaves behind, for ever. The token is an opaque string
/// to the gateway (`gateway/src/tools/find.rs` passes it through) and a plain
/// bound to task-db, so a bound derived from the id reads the one page the id
/// is on, however many tasks lie before it. A prefix always sorts below the
/// string it prefixes, so the id is never skipped.
///
/// No delete right is needed, and the tasks stay: this bounds the READ.
pub fn listing_token(id: &str) -> Result<String> {
    let mut cut = id.chars();
    anyhow::ensure!(
        cut.next_back().is_some(),
        "an empty task id has no listing token"
    );
    Ok(cut.as_str().to_string())
}

/// The `find_tasks` arguments for the one bounded page that must list `id`.
/// The key names are the gateway's schema; a misspelled one is ignored there,
/// not refused.
pub fn listing_args(id: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "page_size": LISTING_PAGE_SIZE,
        "page_token": listing_token(id)?,
    }))
}

/// Succeed if the `find_tasks` answer lists a task with `id`.
///
/// **FAIL-CLOSED.** An answer without the id is an error, with no fallback walk:
/// a store that stopped honouring the token (an opaque or validated one, a
/// changed sort) must turn the row red, not be hidden by a slow second try.
pub fn ensure_listed(id: &str, answer: &serde_json::Value) -> Result<()> {
    let tasks = answer["tasks"]
        .as_array()
        .with_context(|| format!("find_tasks carried no `tasks` array: {answer}"))?;
    anyhow::ensure!(
        tasks.iter().any(|t| t["id"] == serde_json::json!(id)),
        "{id} is not on the {} task(s) the bounded page listed",
        tasks.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const ID: &str = "yadgar:task:01a1640d-6e8a-74ca-91bb-abca6faea485";

    /// A task as `find_tasks` lists it.
    fn row(id: &str) -> Value {
        json!({ "id": id })
    }

    /// THE WHOLE POINT (yaadgaar 269). The listing row reads ONE bounded page,
    /// whose start is derived from the id it is looking for, so its cost does
    /// not grow with the two tasks every run leaves behind.
    #[test]
    fn the_token_is_the_id_without_its_last_character() {
        assert_eq!(
            listing_token(ID).unwrap(),
            "yadgar:task:01a1640d-6e8a-74ca-91bb-abca6faea48"
        );
    }

    /// `ORDER BY id` with `id > token` returns the token's successors, so the
    /// token must sort BELOW the id or the id is skipped. A prefix always does.
    #[test]
    fn the_token_sorts_below_the_id() {
        assert!(listing_token(ID).unwrap().as_str() < ID);
    }

    /// An empty id has no prefix: refuse it rather than ask for the first page,
    /// which would pass or fail on whatever the oldest task is.
    #[test]
    fn an_empty_id_has_no_token() {
        assert!(listing_token("").is_err());
    }

    /// The key names are the gateway's `find_tasks` schema
    /// (`gateway/src/tools/find.rs`): `page_size` and `page_token`. A misspelled
    /// key is silently ignored there, so the row would read the default first
    /// page for ever and look as though it had looked.
    #[test]
    fn the_listing_arguments_use_the_gateways_key_names() {
        assert_eq!(
            listing_args(ID).unwrap(),
            json!({
                "page_size": LISTING_PAGE_SIZE,
                "page_token": "yadgar:task:01a1640d-6e8a-74ca-91bb-abca6faea48",
            })
        );
    }

    /// The page must be wide enough for every id that can sort between the
    /// token and the id: they share all but the last character, so there are at
    /// most sixteen hex digits of them, the id among them.
    #[test]
    fn the_page_holds_every_sibling_the_last_character_can_make() {
        const { assert!(LISTING_PAGE_SIZE >= 16) };
    }

    #[test]
    fn a_page_that_lists_the_id_passes() {
        let answer = json!({ "tasks": [row("yadgar:task:x0"), row(ID)], "next_page_token": "" });
        assert!(ensure_listed(ID, &answer).is_ok());
    }

    /// A page without the id is red, with the id named. No fallback walk: a
    /// token the store stopped honouring must not be hidden by one.
    #[test]
    fn a_page_without_the_id_is_an_error_naming_it() {
        let answer = json!({ "tasks": [row("yadgar:task:other")], "next_page_token": "" });
        let e = ensure_listed(ID, &answer).unwrap_err().to_string();
        assert!(e.contains(ID), "{e}");
    }

    #[test]
    fn an_empty_page_is_an_error() {
        let answer = json!({ "tasks": [], "next_page_token": "" });
        assert!(ensure_listed(ID, &answer).is_err());
    }

    /// A page with no `tasks` array is a malformed answer, not an empty one.
    #[test]
    fn a_page_without_a_tasks_array_is_an_error() {
        let answer = json!({ "nope": [] });
        let e = ensure_listed(ID, &answer).unwrap_err().to_string();
        assert!(e.contains("tasks"), "{e}");
    }
}
