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
    /// Every `Service:port` in the `yadgar` namespace, as last measured. C-18
    /// either dials each one or names it in `excluded` with a reason. Required,
    /// with no default: an absent inventory would make the closed-set check pass
    /// over nothing.
    pub inventory: Vec<String>,
    /// The day `inventory` was read off the live cluster, `YYYY-MM-DD`.
    pub inventory_measured: String,
    /// Inventory entries C-18 deliberately does not dial, each with its reason.
    pub excluded: Vec<Excluded>,
}

/// One inventory entry C-18 does not dial, and why.
#[derive(Debug, Deserialize)]
pub struct Excluded {
    pub target: String,
    pub reason: String,
}

/// Why `c` is not a closed set over its inventory, one line per defect.
///
/// Empty means closed: every inventory entry is a target or an exclusion,
/// nothing is both, every target and exclusion is in the inventory, nothing is
/// listed twice, and every exclusion says why. A function rather than inline
/// test code so each defect class has its own red case (ADR-0645).
pub fn confinement_gaps(c: &Confinement) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut gaps = Vec::new();
    let inventory: BTreeSet<&str> = c.inventory.iter().map(String::as_str).collect();
    let targets: BTreeSet<&str> = c.targets.iter().map(String::as_str).collect();
    let excluded: BTreeSet<&str> = c.excluded.iter().map(|e| e.target.as_str()).collect();
    if inventory.is_empty() {
        gaps.push("the inventory is empty, so the closed-set check would pass over nothing".into());
    }
    if !is_iso_date(&c.inventory_measured) {
        gaps.push(format!(
            "inventory_measured `{}` is not a YYYY-MM-DD date",
            c.inventory_measured
        ));
    }
    for (what, list, set) in [
        (
            "inventory",
            c.inventory.iter().collect::<Vec<_>>(),
            &inventory,
        ),
        ("targets", c.targets.iter().collect(), &targets),
        (
            "excluded",
            c.excluded.iter().map(|e| &e.target).collect(),
            &excluded,
        ),
    ] {
        if list.len() != set.len() {
            gaps.push(format!("`{what}` names an entry more than once"));
        }
    }
    for entry in &inventory {
        if !targets.contains(entry) && !excluded.contains(entry) {
            gaps.push(format!(
                "`{entry}` is in the inventory but is neither a target nor excluded"
            ));
        }
    }
    for entry in targets.intersection(&excluded) {
        gaps.push(format!("`{entry}` is both a target and excluded"));
    }
    for entry in targets.union(&excluded) {
        if !inventory.contains(entry) {
            gaps.push(format!(
                "`{entry}` is not in the inventory measured {}; re-measure and add it",
                c.inventory_measured
            ));
        }
    }
    for e in &c.excluded {
        if e.reason.trim().is_empty() {
            gaps.push(format!("`{}` is excluded with no reason", e.target));
        }
    }
    gaps
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
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
        std::env::var("ESTATE_EDGE_PORT") // ADR-0569-EXCEPTION(CC): overrides reference.toml's edge.port, a declared value, not a default nobody chose.
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

    /// Every database tier C-18 names is named on BOTH of its faces: the gRPC
    /// Service `<tier>` and the MariaDB Service `<tier>-mariadb` behind it.
    ///
    /// Ledger 751: the list named `task-db` and not `task-db-mariadb`, so the
    /// runner's reach to one database went unmeasured while the row reported
    /// green. The pairing is structural, not a list of names — a service name in
    /// a `.rs` file is the compiled-in dependency D80's gate refuses — so it
    /// catches a missing `-mariadb` sibling. It cannot catch a tier that is
    /// missing on both faces; `reference.toml` records the live Service list
    /// the targets were measured against.
    #[test]
    fn every_confined_database_tier_is_named_with_its_mariadb() {
        const MARIADB: &str = "-mariadb";
        let r = Reference::load().expect("reference.toml parses");
        let hosts: Vec<&str> = r
            .confinement
            .targets
            .iter()
            .map(|t| t.split(['.', ':']).next().unwrap_or(t))
            .collect();
        for host in &hosts {
            let tier = host.strip_suffix(MARIADB).unwrap_or(host);
            let mariadb = format!("{tier}{MARIADB}");
            if host.ends_with(MARIADB) || tier.ends_with("-db") {
                assert!(
                    hosts.contains(&tier) && hosts.contains(&mariadb.as_str()),
                    "C-18 names `{host}` but not both `{tier}` and `{mariadb}`; a database tier \
                     confined on one face is reachable-unmeasured on the other"
                );
            }
        }
    }

    /// Every `yadgar` Service:port is a C-18 target or an explicit exclusion.
    ///
    /// Ledger 1243 (yaadgaar #362): the list named the seven database and
    /// valkey faces and none of `iam`, `task`, `project` :50052, `nats` :4222 or
    /// `gateway` :8080, so the runner's reach to the three logic tiers, the
    /// broker and the gateway's in-cluster Service was never measured. The
    /// `-mariadb` pairing test above cannot see a tier missing on every face;
    /// this one can, against the measured inventory in `reference.toml`.
    #[test]
    fn every_measured_service_is_a_confinement_target_or_excluded() {
        let r = Reference::load().expect("reference.toml parses");
        let gaps = confinement_gaps(&r.confinement);
        assert!(
            gaps.is_empty(),
            "C-18 is not closed over the `yadgar` Services measured {}:\n{}",
            r.confinement.inventory_measured,
            gaps.join("\n")
        );
    }

    /// Each defect class `confinement_gaps` refuses, as its own red case, plus
    /// the pristine companion (ADR-0645, ADR-0646). The names are synthetic
    /// (`a:1`, `b:2`), not cluster Services, so D80 has nothing to refuse.
    #[test]
    fn confinement_gaps_refuses_each_defect_and_passes_a_closed_set() {
        fn c(targets: &[&str], inventory: &[&str], excluded: &[(&str, &str)]) -> Confinement {
            Confinement {
                targets: targets.iter().map(|s| s.to_string()).collect(),
                connect_timeout_ms: 1,
                inventory: inventory.iter().map(|s| s.to_string()).collect(),
                inventory_measured: "2026-10-17".into(),
                excluded: excluded
                    .iter()
                    .map(|(t, r)| Excluded {
                        target: t.to_string(),
                        reason: r.to_string(),
                    })
                    .collect(),
            }
        }
        let has = |c: &Confinement, needle: &str| {
            let g = confinement_gaps(c);
            assert!(
                g.iter().any(|l| l.contains(needle)),
                "{needle:?} not in {g:?}"
            );
        };
        // Pristine: one target, one exclusion, inventory is exactly the two.
        assert_eq!(
            confinement_gaps(&c(&["a:1"], &["a:1", "b:2"], &[("b:2", "same pod")])),
            Vec::<String>::new()
        );
        // An inventory entry that is neither.
        has(
            &c(&["a:1"], &["a:1", "b:2"], &[]),
            "`b:2` is in the inventory but is neither",
        );
        // Both a target and excluded.
        has(
            &c(&["a:1"], &["a:1"], &[("a:1", "x")]),
            "`a:1` is both a target and excluded",
        );
        // A target the inventory does not know.
        has(
            &c(&["a:1", "z:9"], &["a:1"], &[]),
            "`z:9` is not in the inventory",
        );
        // An exclusion the inventory does not know.
        has(
            &c(&["a:1"], &["a:1"], &[("z:9", "x")]),
            "`z:9` is not in the inventory",
        );
        // An exclusion with no reason.
        has(
            &c(&["a:1"], &["a:1", "b:2"], &[("b:2", "  ")]),
            "`b:2` is excluded with no reason",
        );
        // A duplicate in each list.
        has(
            &c(&["a:1", "a:1"], &["a:1"], &[]),
            "`targets` names an entry more than once",
        );
        has(
            &c(&["a:1"], &["a:1", "a:1"], &[]),
            "`inventory` names an entry more than once",
        );
        has(
            &c(&["a:1"], &["a:1", "b:2"], &[("b:2", "x"), ("b:2", "x")]),
            "`excluded` names an entry more than once",
        );
        // An empty inventory, which would make the check vacuous.
        has(&c(&[], &[], &[]), "the inventory is empty");
        // A measurement date that is not a date.
        let mut bad = c(&["a:1"], &["a:1"], &[]);
        bad.inventory_measured = "recently".into();
        has(&bad, "is not a YYYY-MM-DD date");
    }

    /// C-18's valkey target must name the port valkey actually serves.
    ///
    /// argocd#90 (B-V4.3, live 2026-10-10) moved valkey to TLS-only: the
    /// Service exposes `valkey-tls` on 6380, `valkey-ingress` admits 6380
    /// only from `app=gateway`, and the pod runs `--port 0` so nothing
    /// listens on 6379 any more. A target that still names 6379 is not
    /// merely stale: nobody listens there, so C-18's TCP connect fails for a
    /// reason that has nothing to do with the NetworkPolicy this row exists
    /// to test — the same vacuous pass the row's own doctrine (see
    /// `confinement.rs`) already guards against for an unresolvable name,
    /// here produced by a closed port instead of a missing one.
    #[test]
    fn the_valkey_confinement_target_names_the_live_port() {
        let r = Reference::load().expect("reference.toml parses");
        assert!(
            r.confinement
                .targets
                .iter()
                // d80: exempt - asserts against reference.toml's own declared value, not a compiled-in dependency
                .any(|t| t == "valkey.yadgar.svc.cluster.local:6380"),
            "C-18 must target valkey's live TLS port 6380"
        );
        assert!(
            !r.confinement.targets.iter().any(|t| t.contains(":6379")),
            "6379 is dead since argocd#90 (valkey runs --port 0); a target on a closed port \
             passes C-18 for the wrong reason, not because the NetworkPolicy denied it"
        );
    }

    /// The declared tool surface names every tool the gateway serves.
    ///
    /// gateway#96 (v0.9.54) added `edit_task` and `transition_task` to what
    /// `tools/list` answers; `reference.toml` still declared only the three
    /// tools that predated it. C-06 (`crates/front/tests/smoke.rs`) dials
    /// the live cluster and would have caught the drift there, but C-06 is
    /// `#[ignore]`d outside the estate-front runner, so a stale declaration
    /// can sit unmeasured between smoke runs. This test pins the same
    /// closed set with no cluster: a `reference.toml` edit that drops a
    /// served tool or leaves a retired one fails here first.
    #[test]
    fn the_declared_tool_surface_is_the_closed_set_gateway_serves() {
        let r = Reference::load().expect("reference.toml parses");
        let mut declared = r.mcp.tools.clone();
        declared.sort();
        let mut expected = vec![
            // d80: exempt - asserts against reference.toml's own declared value, not a compiled-in dependency
            "create_task".to_string(),
            "edit_task".to_string(),
            "find_tasks".to_string(),
            "list_projects".to_string(),
            "read_task".to_string(),
            "transition_task".to_string(),
        ];
        expected.sort();
        assert_eq!(
            declared, expected,
            "reference.toml's mcp.tools is {declared:?}; the gateway serves {expected:?} \
             (gateway#96, v0.9.54) — C-06 compares against whatever is declared here, so a \
             stale or incomplete declaration makes closed-set equality pass for the wrong reason"
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
