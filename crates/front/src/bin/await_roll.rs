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
//! no cluster access. Every module but the gateway has no such front door. For them
//! this program REFUSES: it says on the run that the roll cannot be confirmed and
//! exits non-zero, so no row runs and no verdict is reported.
//!
//! **THIS SAID "this program prints, on the run itself, that the rolled digest
//! could not be confirmed as serving and that the verdict may describe the
//! previous pods" — and then exited zero.** Stating the doubt on a run that ends
//! green was measured six times as a false green (ledger 675): the rows ran in
//! the two seconds after the message and certified the pre-roll estate. A roll
//! dispatch naming nothing, and a roll named by half, refuse for the same reason.
//! Stage 3's A-04 replaces the refusal with digest parity for every module.
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

    // WHICH EVENT STARTED THIS RUN, set by GitHub on every runner. It tells a
    // roll dispatch that arrived naming nothing apart from a person asking to
    // measure what is deployed. Off a runner it is absent, which is the second.
    let event = std::env::var("GITHUB_EVENT_NAME").ok(); // ADR-0569-EXCEPTION: a run input, not a knob.

    match decide(event.as_deref(), &module, &tag) {
        Decision::Proceed(message) => {
            report(&message);
            return Ok(());
        }
        Decision::Refuse(message) => {
            report(&message);
            anyhow::bail!("no verdict: the roll this run was handed cannot be confirmed (above)");
        }
        Decision::PollGateway => {}
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

/// What this run may do about the roll it was handed.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Let the suite run, having said this on the run.
    Proceed(String),
    /// Report no verdict: say why on the run and exit non-zero.
    Refuse(String),
    /// The gateway was rolled: poll the edge until it serves the tag.
    PollGateway,
}

/// The decision, over values rather than over the process environment, so
/// every arm is assertable without a runner.
///
/// **A VERDICT THIS RUN CANNOT ATTRIBUTE IS REFUSED, NOT REPORTED** (ledger
/// 675, `yadgarhq/docs` `plans/settled-state-smoke-gate.md`). Arms 1 and 2 used
/// to print that they could not confirm the roll and then return `Ok`, so nine
/// rows ran and the workflow reported SUCCESS about the previous pods — six
/// measured false greens. `smoke.yaml` is this binary's only caller, and the
/// only reader of smoke's conclusion is a person: `ci-release.yaml` checks that
/// a run was CREATED and never reads how it ended. So a non-zero exit breaks no
/// machine caller. It stops the rows, and the run ends red with this text.
///
/// The one arm that still proceeds without waiting is a run nobody tied to a
/// roll — `workflow_dispatch` with no module and no tag, or the binary off a
/// runner. That is a request to measure what is deployed, and it is the
/// recovery every refusal below names.
fn decide(event: Option<&str>, module: &str, tag: &str) -> Decision {
    const RECOVERY: &str = "To get a verdict, wait for Argo CD to finish rolling (pin to \
        serving measured 285-290s; pin to pod start up to 303s), then start `smoke` by `workflow_dispatch` with `module` and \
        `tag` left empty. That run measures what is deployed and says so.";

    match (module.is_empty(), tag.is_empty()) {
        (true, true) if event == Some("repository_dispatch") => Decision::Refuse(format!(
            "**This run refuses to report a verdict.** A `module-rolled` dispatch arrived naming \
             no module and no tag, so a roll happened and this run cannot say which. {RECOVERY}"
        )),
        (true, true) => Decision::Proceed(
            "No roll was named, so there is nothing to wait for. This run measures whatever is \
             currently deployed."
                .to_string(),
        ),
        (true, false) | (false, true) => Decision::Refuse(format!(
            "**This run refuses to report a verdict.** A roll was half named — module \
             `{module}`, tag `{tag}` — and a roll needs both to be waited for. {RECOVERY}"
        )),
        (false, false) if module != "gateway" => Decision::Refuse(format!(
            "**This run refuses to report a verdict.** `{module}` was rolled to `{tag}`, and \
             only the gateway states its own release version through the front door, so the \
             rows would measure pods this run cannot tell from the PREVIOUS ones. Stage 3's \
             annex row A-04 closes this by comparing the deployed image digest to the dispatched \
             one, for every module. {RECOVERY}"
        )),
        (false, false) => Decision::PollGateway,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const DISPATCH: Option<&str> = Some("repository_dispatch");
    const MANUAL: Option<&str> = Some("workflow_dispatch");

    fn refused(d: &Decision) -> bool {
        matches!(d, Decision::Refuse(_))
    }

    /// Arm 2, the measured false green (ledger 675): a non-gateway roll cannot be
    /// confirmed from the front door, so the run must refuse to report a verdict
    /// rather than let nine rows certify the previous pods.
    #[test]
    fn a_roll_that_cannot_be_confirmed_refuses_the_verdict() {
        for module in ["iam", "iam-db", "task", "task-db", "project"] {
            let d = decide(DISPATCH, module, "v1.2.3");
            assert!(refused(&d), "{module}: {d:?}");
            let d = decide(MANUAL, module, "v1.2.3");
            assert!(refused(&d), "{module} named by hand: {d:?}");
        }
    }

    /// Arm 1 on a roll dispatch: `module-rolled` arrived naming no roll. Something
    /// rolled and this run cannot say what, so it is not a "measure what is
    /// deployed" run either.
    #[test]
    fn a_roll_dispatch_that_names_nothing_refuses_the_verdict() {
        assert!(refused(&decide(DISPATCH, "", "")));
        assert!(refused(&decide(DISPATCH, "task", "")));
        assert!(refused(&decide(DISPATCH, "", "v1.2.3")));
    }

    /// Half a roll named by hand is an operator mistake, not a request to measure
    /// what is deployed: refusing says so, proceeding would hide it.
    #[test]
    fn half_a_roll_named_by_hand_refuses_the_verdict() {
        assert!(refused(&decide(MANUAL, "gateway", "")));
        assert!(refused(&decide(MANUAL, "", "v1.2.3")));
    }

    /// The one honest no-wait arm: a person asked to measure what is deployed, or
    /// the binary runs off a runner. This is also the recovery path the refusals
    /// name, so it must stay open.
    #[test]
    fn a_manual_run_naming_no_roll_measures_what_is_deployed() {
        assert!(matches!(decide(MANUAL, "", ""), Decision::Proceed(_)));
        assert!(matches!(decide(None, "", ""), Decision::Proceed(_)));
    }

    /// Arm 3 is unchanged: the gateway is confirmed by polling the edge.
    #[test]
    fn a_gateway_roll_is_polled() {
        assert_eq!(decide(DISPATCH, "gateway", "v0.9.3"), Decision::PollGateway);
        assert_eq!(decide(MANUAL, "gateway", "v0.9.3"), Decision::PollGateway);
    }

    /// Every refusal names the way back to a verdict, because a red with no
    /// next step is read as a broken suite.
    #[test]
    fn every_refusal_names_the_recovery() {
        for d in [
            decide(DISPATCH, "task", "v1.2.3"),
            decide(DISPATCH, "", ""),
            decide(MANUAL, "gateway", ""),
        ] {
            let Decision::Refuse(message) = d else {
                panic!("expected a refusal, got {d:?}");
            };
            assert!(message.contains("workflow_dispatch"), "{message}");
        }
    }
}
