//! `reference.toml`, typed.
//!
//! The suite asserts against DECLARED values, never against literals buried in
//! test code. See the header of `reference.toml` for why.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Every declared constant the stage-1 rows read.
#[derive(Debug, Deserialize)]
pub struct Reference {
    pub edge: Edge,
    pub identity: Identity,
    pub mcp: Mcp,
    pub login: Login,
    pub confinement: Confinement,
}

/// The names of the two standing identities the ceremony creates.
///
/// DECLARED HERE RATHER THAN COMPILED IN (ADR-0569). They were
/// `DEFAULT_USERNAME` and `DEFAULT_USERNAME_2` in `estate-front`, behind an
/// `ESTATE_USERNAME` read nothing ever set. The passwords are NOT here: they
/// arrive from the `estate` GitHub environment and are read by `estate-front`.
#[derive(Debug, Deserialize)]
pub struct Identity {
    pub primary: String,
    pub secondary: String,
}

#[derive(Debug, Deserialize)]
pub struct Edge {
    pub host: String,
    pub port: u16,
    pub root_pem: String,
}

#[derive(Debug, Deserialize)]
pub struct Mcp {
    pub protocol_version: String,
    pub server_name: String,
    pub result_type: String,
    pub tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Login {
    pub allowed_headers: Vec<String>,
    pub refusal_body: String,
    pub refusal_status: u16,
}

#[derive(Debug, Deserialize)]
pub struct Confinement {
    pub targets: Vec<String>,
    pub connect_timeout_ms: u64,
    pub deadline_task: String,
    pub deadline_date: String,
    pub deadline_summary: String,
}

/// The repository root, derived from this crate's manifest directory.
///
/// Derived rather than searched for: a walk upwards looking for `reference.toml`
/// would find a different repository's file if this one were ever vendored, and
/// the failure would be a suite asserting another estate's constants.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .to_path_buf()
}

impl Reference {
    /// Read and parse `reference.toml`.
    ///
    /// Fails loudly. There is no default: a suite that ran with built-in values
    /// when the file was unreadable would assert something nobody declared.
    pub fn load() -> Result<Self> {
        let path = repo_root().join("reference.toml");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The committed name-constrained root, as PEM bytes.
    pub fn root_pem(&self) -> Result<Vec<u8>> {
        let path = repo_root().join(&self.edge.root_pem);
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }

    /// The port the edge is dialled on.
    ///
    /// `ESTATE_EDGE_PORT` overrides it, and the override is for one situation:
    /// running the suite from a workstation, where the reference cluster's edge
    /// is published on a NodePort rather than on 443. It changes WHERE the
    /// client connects and nothing about what it trusts — the name in the URL,
    /// the SNI and the certificate validated are the same either way.
    ///
    /// **ADR-0569 EXCEPTION, AND THE ARGUMENT IS THE DISCRIMINATOR.** ADR-0569
    /// forbids three things: a compiled-in default, a system-level fallback, and
    /// a last-resort constant. `self.edge.port` is none of the three. It is
    /// `reference.toml`, which IS the declared source for this repository —
    /// the file's own header exists to say that a value the suite asserts
    /// against must be a line somebody can read and edit rather than a literal
    /// buried in test code. So there is no value here that nobody chose, which
    /// is the whole of what the rule is about. Contrast
    /// `estate_front::Identity`, where the fallback WAS a constant in the source
    /// and was therefore deleted rather than excepted.
    ///
    /// `scripts/enrol.sh` line 35 already implements exactly this precedence for
    /// exactly this knob — `ESTATE_EDGE_PORT` over the port it reads out of
    /// `reference.toml` — so this is written-down practice in this repository
    /// rather than a case invented to keep a line.
    pub fn port(&self) -> u16 {
        // THE MARKER IS A TRAILING COMMENT rather than a line of its own, and it
        // has to be: the gate rejoins a `cargo fmt`-broken method chain before
        // matching, then filters the JOINED line for the marker — so a marker on
        // the line above is not on the text the filter reads.
        std::env::var("ESTATE_EDGE_PORT") // ADR-0569-EXCEPTION: see the doc comment above.
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(self.edge.port)
    }

    /// The base URL every row dials.
    pub fn base_url(&self) -> String {
        format!("https://{}:{}", self.edge.host, self.port())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed file must parse into the shape the rows read.
    ///
    /// This runs on any runner, with no cluster: it is the one check that a
    /// `reference.toml` edit — the reviewed one-line change the file exists to
    /// invite — has not broken every row at once.
    #[test]
    fn the_committed_reference_parses() {
        let r = Reference::load().expect("reference.toml parses");
        assert_eq!(r.mcp.protocol_version, "2026-07-28");
        assert!(!r.mcp.tools.is_empty(), "the tool set must be declared");
        assert!(
            !r.login.allowed_headers.is_empty(),
            "an empty allowlist would admit every header, which is the opposite of a closed set"
        );
        assert!(
            !r.confinement.targets.is_empty(),
            "C-18 with no targets is a row that cannot fail"
        );

        // THE IDENTITY NAMES, which have no compiled-in fallback behind them any
        // more (ADR-0569). An empty name reaches `POST /auth/login` as `""`, and
        // C-03's positive control would then fail with an account-enumeration
        // diagnostic for what is really an unparsed reference file — so the
        // emptiness is caught HERE, by the one test that runs without a cluster.
        assert!(
            !r.identity.primary.is_empty(),
            "identity.primary must name the first standing identity; there is no default behind it"
        );
        assert!(
            !r.identity.secondary.is_empty(),
            "identity.secondary must name the second standing identity; there is no default behind it"
        );
        assert_ne!(
            r.identity.primary, r.identity.secondary,
            "the confinement rows need two DIFFERENT identities; one name twice makes C-20 pass \
             by comparing an identity with itself"
        );
    }

    /// The root is committed and is a certificate.
    #[test]
    fn the_committed_root_is_readable_pem() {
        let r = Reference::load().expect("reference.toml parses");
        let pem = r.root_pem().expect("ca/root.pem is readable");
        let text = String::from_utf8(pem).expect("PEM is text");
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----"));
    }
}
