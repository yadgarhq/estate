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

/// The page size a listing row asks for: task-db's `MAX_PAGE`, so the walk
/// below takes as few round trips as the store allows. A larger value is
/// clamped by task-db, never refused, so this cannot break a row.
pub const LISTING_PAGE_SIZE: u32 = 500;

/// The most pages a listing row reads before it gives up. At
/// [`LISTING_PAGE_SIZE`] that is 100,000 visible tasks; a run adds two.
pub const LISTING_PAGE_CAP: usize = 200;

/// The `find_tasks` arguments for one page of a listing walk: the page size,
/// and the previous page's token when there is one. The key names are the
/// gateway's schema; a misspelled one is ignored there, not refused.
pub fn listing_args(token: Option<String>) -> serde_json::Value {
    let mut args = serde_json::json!({ "page_size": LISTING_PAGE_SIZE });
    if let Some(t) = token {
        args["page_token"] = serde_json::json!(t);
    }
    args
}

/// Walk `find_tasks` pages until a task with `id` is listed, and return the
/// 1-based page it was on.
///
/// **WHY A WALK, AND NOT ONE PAGE (ledger 1244).** task-db lists in
/// `ORDER BY id` — UUIDv7, so OLDEST first — and the project is now shared by
/// every run. A task created now is therefore on the LAST page once earlier
/// runs have filled the first; a row that read one page would turn red after
/// about twenty-five runs having found no defect at all. (The gateway's tool
/// catalogue says "newest first"; task-db's query says otherwise, and the
/// query is what answers.)
///
/// `fetch` is handed `None` for the first page and the previous page's
/// `next_page_token` after that. An empty token ends the walk. The walk is
/// bounded by `cap`, so a store that never stops handing out tokens ends the
/// row red with the cap named rather than hanging it, and a token answered
/// back unchanged ends it at once as a loop.
pub async fn find_listed<F, Fut>(id: &str, cap: usize, mut fetch: F) -> Result<usize>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: std::future::Future<Output = Result<serde_json::Value>>,
{
    let mut token: Option<String> = None;
    for page in 1..=cap {
        let answer = fetch(token.clone()).await?;
        let tasks = answer["tasks"].as_array().with_context(|| {
            format!("find_tasks page {page} carried no `tasks` array: {answer}")
        })?;
        if tasks.iter().any(|t| t["id"] == serde_json::json!(id)) {
            return Ok(page);
        }
        match answer["next_page_token"].as_str() {
            // A LOOP, NOT A LONG LISTING. Keyset paging moves the token on
            // every page; one answered back unchanged would be read again and
            // again until the cap, and the row would blame the cap.
            Some(next) if token.as_deref() == Some(next) => anyhow::bail!(
                "find_tasks answered page {} with the same next_page_token it was handed \
                 ({next}); the listing is looping",
                page
            ),
            Some(next) if !next.is_empty() => token = Some(next.to_string()),
            _ => anyhow::bail!("{id} is on none of the {page} page(s) find_tasks listed"),
        }
    }
    anyhow::bail!("{id} was not found before the cap of {cap} pages")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// A fake store: each page is what `find_tasks` would answer for the token
    /// that names it. The first page answers the absent token.
    fn pages<'a>(
        spec: &'a [(&'a [&'a str], &'a str)],
    ) -> impl FnMut(Option<String>) -> std::future::Ready<Result<Value>> + 'a {
        move |token: Option<String>| {
            let i = match token {
                None => 0,
                Some(t) => {
                    spec.iter()
                        .position(|(ids, _)| ids.last() == Some(&t.as_str()))
                        .expect("a token the fake handed out")
                        + 1
                }
            };
            let (ids, next) = spec[i];
            let tasks: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
            std::future::ready(Ok(json!({ "tasks": tasks, "next_page_token": next })))
        }
    }

    #[tokio::test]
    async fn a_task_on_the_first_page_is_found_on_page_one() {
        let spec: &[(&[&str], &str)] = &[(&["a", "b"], "")];
        assert_eq!(find_listed("b", 5, pages(spec)).await.unwrap(), 1);
    }

    /// THE CASE THE SHARED PROJECT CREATES. `find_tasks` answers oldest first,
    /// so a task created now sits on the LAST page once older runs fill the
    /// first. A walk that stopped at page one would call it missing.
    #[tokio::test]
    async fn a_task_past_the_first_page_is_found_by_following_the_token() {
        let spec: &[(&[&str], &str)] = &[(&["a", "b"], "b"), (&["c", "d"], "d"), (&["e"], "")];
        assert_eq!(find_listed("e", 5, pages(spec)).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn a_task_on_no_page_is_an_error_naming_how_many_pages_were_read() {
        let spec: &[(&[&str], &str)] = &[(&["a"], "a"), (&["b"], "")];
        let e = find_listed("z", 5, pages(spec))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("2 page"), "{e}");
    }

    /// The walk is bounded. A store that hands out a next token for ever must
    /// end the row red with the cap named, not hang it until the job times out.
    #[tokio::test]
    async fn the_walk_stops_at_the_cap_and_says_so() {
        let spec: &[(&[&str], &str)] = &[(&["a"], "a"), (&["b"], "b"), (&["c"], "c"), (&["d"], "")];
        let e = find_listed("d", 2, pages(spec))
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("cap of 2"), "{e}");
    }

    /// A page with no `tasks` array is a malformed answer, not an empty one.
    #[tokio::test]
    async fn a_page_without_a_tasks_array_is_an_error() {
        let fetch = |_: Option<String>| std::future::ready(Ok(json!({ "nope": [] })));
        assert!(find_listed("a", 5, fetch).await.is_err());
    }

    /// A store that answers the same `next_page_token` it was handed is looping,
    /// and the walk says so at once instead of spending the whole cap on it.
    #[tokio::test]
    async fn a_repeated_token_ends_the_walk_as_a_loop() {
        let fetch = |_: Option<String>| {
            std::future::ready(Ok(json!({ "tasks": [], "next_page_token": "t" })))
        };
        let e = find_listed("a", 50, fetch).await.unwrap_err().to_string();
        assert!(e.contains("same next_page_token"), "{e}");
        assert!(e.contains("page 2"), "{e}");
    }

    /// The key names are the gateway's `find_tasks` schema
    /// (`gateway/src/tools.rs`): `page_size` and `page_token`. A misspelled key
    /// is silently ignored there, so C-10 would read default-size first pages
    /// for ever and still look like it walked.
    #[test]
    fn the_listing_arguments_use_the_gateways_key_names() {
        assert_eq!(
            listing_args(None),
            json!({ "page_size": LISTING_PAGE_SIZE })
        );
        assert_eq!(
            listing_args(Some("yadgar:task:x".into())),
            json!({ "page_size": LISTING_PAGE_SIZE, "page_token": "yadgar:task:x" })
        );
    }
}
