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
    /// `X-Yadgar-Project` for this run, `estate/<run-id>-<run-attempt>`.
    pub project: String,
}

impl Suite {
    pub fn open() -> Result<Self> {
        let reference = Reference::load()?;
        let edge = Edge::trusting_committed_root(&reference)?;
        Ok(Self {
            reference,
            edge,
            project: run::project_id(),
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
