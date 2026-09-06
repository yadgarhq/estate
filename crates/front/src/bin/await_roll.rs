//! Wait until the rolled code is the code the suite is about to measure.
//!
//! **THE PROBLEM THIS SOLVES IS A FALSE GREEN, WHICH IS THE WORST KIND.** A roll
//! fires `repository_dispatch` the moment the release job writes
//! `versions/<module>.yaml`; Argo CD syncs some seconds or minutes later. A
//! smoke run that wins that race measures the PREVIOUS pods and reports green
//! for code that is not running.
//!
//! **THE GATEWAY CAN BE CONFIRMED FROM THE FRONT DOOR ALONE, AND ONLY THE
//! GATEWAY.** `server/discover` reports `crate::VERSION`, which `build.rs` takes
//! from `YADGAR_GATEWAY_VERSION` and the `Containerfile` sets from the release
//! version — so the running binary states its own release, unauthenticated, with
//! no cluster access. The other four modules have no such front door. For them
//! this program prints, on the run itself, that the rolled digest could not be
//! confirmed as serving and that the verdict may describe the previous pods. An
//! unconfirmed roll is STATED on the run that could not confirm it, never left
//! for a reader to infer. Stage 3's A-04 replaces both halves with digest parity
//! for all five.
//!
//! **COMPARE NORMALISED, NEVER RAW.** `ci-release.yaml`'s `detect` step strips
//! the leading `v` (`VERSION="${VERSION#v}"`), so the tag is `v0.8.13` and the
//! served version is `0.8.13`. A literal equality poll would time out on every
//! single roll, and every roll would look like a failed one.

use std::time::{Duration, Instant};

use anyhow::Result;
use estate_harness::{client::Edge, mcp, reference::Reference};
use serde_json::json;

/// Argo CD sync latency is why this polls rather than asserting once. The number
/// is a starting point to tune against observed sync times, not a measurement.
const BUDGET: Duration = Duration::from_secs(600);
const INTERVAL: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    // **ADR-0569 EXCEPTION — THESE ARE NOT CONFIGURATION.** ADR-0569 governs a
    // configuration knob: a value an operator sets for a process, read from one
    // source, whose absence is a mistake worth refusing the boot over. These two
    // are the RUN'S INPUT — `smoke.yaml` fills them from
    // `github.event.client_payload` on a `module-rolled` dispatch, or from
    // `inputs` on a manual run — and a run with no roll behind it is the ordinary
    // case, not a misconfiguration. There is no seed file that could define them,
    // because they describe THIS invocation rather than this installation.
    //
    // ADR-0569's own revisit trigger names the shape: "a knob appears whose
    // absence leaves the system correct". Absence here is correct and is
    // REPORTED — the next block writes "No roll was named" onto the run itself,
    // so nothing is silently assumed.
    //
    // ABSENT AND EMPTY COLLAPSE DELIBERATELY, which is the opposite of the rule
    // the estate's service binaries follow. There, Helm renders a nulled value as
    // `""` and the two must be told apart. Here BOTH spellings mean "no roll was
    // named", and GitHub Actions produces the empty one for an unset
    // `client_payload` key — so distinguishing them would be two messages for one
    // state.
    let module = std::env::var("ESTATE_ROLLED_MODULE").unwrap_or_default(); // ADR-0569-EXCEPTION: a run input, not a knob.
    let tag = std::env::var("ESTATE_ROLLED_TAG").unwrap_or_default(); // ADR-0569-EXCEPTION: a run input, not a knob.

    if module.is_empty() || tag.is_empty() {
        report(
            "No roll was named, so there is nothing to wait for. This run measures whatever is \
             currently deployed.",
        );
        return Ok(());
    }

    if module != "gateway" {
        report(&format!(
            "**This run could not confirm the roll it is measuring.** `{module}` was rolled to \
             `{tag}`, and only the gateway states its own release version through the front door. \
             This run's verdict may describe the PREVIOUS pods rather than the rolled code. \
             Stage 3's annex row A-04 closes this by comparing the deployed image digest to the \
             dispatched one, for all five modules."
        ));
        return Ok(());
    }

    let want = tag.strip_prefix('v').unwrap_or(&tag).to_string();
    let reference = Reference::load()?;
    let edge = Edge::trusting_committed_root(&reference)?;

    let started = Instant::now();
    let mut last = String::from("(no answer yet)");
    while started.elapsed() < BUDGET {
        match serving_version(&edge, &reference).await {
            Ok(v) if v == want => {
                report(&format!(
                    "The gateway at the edge reports version `{v}`, which is the rolled tag \
                     `{tag}` normalised. This run measures the rolled code."
                ));
                return Ok(());
            }
            Ok(v) => last = v,
            Err(e) => last = format!("(error: {e})"),
        }
        tokio::time::sleep(INTERVAL).await;
    }

    anyhow::bail!(
        "the gateway still reports `{last}` after {}s; the rolled tag `{tag}` normalises to \
         `{want}`. Either the Argo CD sync is slower than this budget — in which case tune the \
         budget rather than the assertion — or the roll did not land.",
        BUDGET.as_secs()
    )
}

/// The version the thing answering on the edge says it is.
async fn serving_version(edge: &Edge, reference: &Reference) -> Result<String> {
    let capture = mcp::post(
        edge,
        reference,
        &mcp::Caller::anonymous(),
        mcp::DISCOVER,
        json!({}),
    )
    .await?;
    let body = capture.json()?;
    body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["version"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no serverInfo version in {}", capture.body_str()))
}

/// Say it on the run, in the place a person reading the run will look.
fn report(message: &str) {
    println!("{message}");
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        if let Ok(mut fh) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            let _ = writeln!(fh, "### Roll confirmation\n\n{message}\n");
        }
    }
}
