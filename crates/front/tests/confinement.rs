//! C-18 — the front-door runner's confinement (ADR-0562, self).
//!
//! **THIS FILE SAID THE ROW IS RED AT BIRTH, AND THE ROW HAS ONLY EVER BEEN
//! OBSERVED GREEN.** The old text read: "**THIS ROW IS RED AT BIRTH AND THE RED
//! IS THE HONEST ALARM.** The cluster's CNI is kindnet, which enforces no
//! NetworkPolicy. The policy in `yadgarhq/deploy`
//! (`infra/estate-front/networkpolicy.yaml`) is therefore the SPECIFICATION this
//! row tests rather than something the network applies, and until the CNI changes
//! this row fails."
//!
//! **THE MEASUREMENT WAS RIGHT AND THE INFERENCE FROM IT WAS WRONG.** It is
//! quoted rather than deleted, because a reader told only "that was wrong"
//! re-measures the CNI, finds kindnet, and derives the same false conclusion.
//! STILL TRUE: the CNI is kindnet and there is no Calico, Cilium or Weave.
//! NO LONGER TRUE: that it enforces nothing. kindnetd `v20260528-9350166c` runs a
//! `kube-network-policies` controller (ledger 684), and ledger 511 proved ingress
//! enforcement live twelve times over.
//!
//! **THE EVIDENCE IS THIS ROW'S OWN RUNTIME.** Nineteen smoke runs, on three
//! separate days, have reached the confinement step, and every one reported `ok`
//! in exactly `18.02s` — six sequential 3000ms timeouts against the six addresses
//! the four declared targets resolve to. A refused connection returns at once;
//! a DROPPED one burns the whole timeout, and that is why the runtime is the
//! reading rather than the step's conclusion: had any one address ACCEPTED, that
//! connect would have returned immediately, this row would have FAILED, and the
//! step would have taken about fifteen seconds. `reference.toml` names all
//! nineteen runs and says which policy refuses which target, because it is not
//! one policy for all four.
//!
//! **THE DEADLINE MACHINERY IS GONE, AND IT WAS REMOVED RATHER THAN RE-DATED
//! (ADR-0687).** This file carried a paragraph reading "**THE RED CARRIES A
//! DEADLINE, AND THAT IS NOT DECORATION.** ADR-0561's own doctrine is that a
//! transient gap is a task with a deadline, never a recorded state … So the
//! failure output names the task that will clear it and the date it should have,
//! both declared in `reference.toml`." It was kept by three `deadline_*` fields
//! and by a `the_deadline_is_a_real_date_and_the_task_is_named` test that was
//! deliberately not `#[ignore]`d. The task those fields named — `yadgarhq/docs`
//! ledger 614 — is WITHDRAWN (docs#51, ADR-0594), so on 2026-10-04 that test
//! would have failed and blocked every merge in this repository over work ruled
//! out five weeks earlier. The doctrine is not wrong; it had no subject left.
//! A deadline whose target has been withdrawn on measurement is removed, because
//! re-dating it preserves a commitment nobody holds and only moves the outage.
//!
//! **IT IS ITS OWN FILE AND ITS OWN CHECK, AND THE REASON GIVEN FOR THAT HAS
//! ALSO EXPIRED.** This paragraph read: "`smoke.yaml` runs this target in a
//! separate step so a standing red does not swallow the verdict of the nine rows
//! that are not red by design. That separation is itself a compromise — it may
//! blunt the alarm — and the deadline is the half worth defending." There is no
//! standing red and there never was, so the separation is protecting nothing from
//! anything. It is kept for the reason that outlived the compromise: C-18 reports
//! as its own NAMED check, so a reader of a run sees the confinement verdict
//! without reading the suite's. What is NOT kept is `continue-on-error`. It
//! excused a red that was never observed, so the step's verdict is now the
//! workflow's (ADR-0687).
//!
//! Read `UNOBSERVED.md` before concluding this row is broken.

use anyhow::Result;
use estate_harness::reference::Reference;
use tokio::net::TcpStream;

/// C-18 (ADR-0562): nothing inside the cluster is reachable from the front-door
/// runner. The edge is the only surface it has.
///
/// "Through the front door" is discipline until the network enforces it. Any
/// suite bug, or any compromised test dependency, can reach a service directly
/// while every row still reports green — so this row asks the network the
/// question rather than trusting the code.
///
/// **THE TARGETS MUST RESOLVE, AND THE ROW FAILS IF THEY DO NOT.** This
/// assertion is that a connection FAILS, so a target whose name does not resolve
/// satisfies it for free and can never go red — a vacuous assertion that would
/// report green forever, including after the CNI lands. The names are therefore
/// resolved first, and a name that resolves to nothing fails the row with its
/// own diagnostic. (The plan this repository implements named
/// `mariadb.mariadb-system.svc:3306` and `iam-db:50052`; neither exists — that
/// namespace holds only the operator webhook, and `iam-db` serves 50051. The
/// declared targets in `reference.toml` were measured against the live cluster.)
#[tokio::test]
#[ignore = "runs inside the estate-front runner; run via `cargo test --test confinement -- --ignored`"]
async fn c18_nothing_inside_the_cluster_is_reachable_from_the_front_door_runner() -> Result<()> {
    let reference = Reference::load()?;
    let c = &reference.confinement;
    let timeout = std::time::Duration::from_millis(c.connect_timeout_ms);

    let mut reachable = Vec::new();
    let mut unresolvable = Vec::new();

    for target in &c.targets {
        match tokio::net::lookup_host(target).await {
            Err(e) => unresolvable.push(format!("{target} ({e})")),
            Ok(addrs) => {
                let addrs: Vec<_> = addrs.collect();
                if addrs.is_empty() {
                    unresolvable.push(format!("{target} (no addresses)"));
                    continue;
                }
                for addr in addrs {
                    if let Ok(Ok(_stream)) =
                        tokio::time::timeout(timeout, TcpStream::connect(addr)).await
                    {
                        reachable.push(format!("{target} at {addr}"));
                    }
                }
            }
        }
    }

    if !unresolvable.is_empty() {
        anyhow::bail!(
            "C-18 CANNOT MEASURE ANYTHING: {unresolvable:?} did not resolve. This row asserts a \
             connection fails, so an unresolvable target passes for free — the row would report \
             green forever. Either this is not running inside the cluster, or the declared \
             targets in reference.toml no longer name live Services."
        );
    }

    anyhow::ensure!(reachable.is_empty(), "{}", c18_failure_message(&reachable));
    Ok(())
}

/// The failure text, which must name what the runner reached.
///
/// It used to name the task that would clear the red and the date it was due,
/// read out of `reference.toml`'s three `deadline_*` fields. Those fields are
/// gone (ADR-0687) and the old pair is quoted inside the message rather than
/// dropped, so that a reader of a red run is not left to rediscover ledger 614
/// and re-derive it as open work.
fn c18_failure_message(reachable: &[String]) -> String {
    format!(
        "C-18 IS RED: the front-door runner opened a TCP connection to {reachable:?}. \
         \"Through the front door\" is not enforced by the network, so any suite bug or \
         compromised test dependency can bypass the edge while every other row reports green.\n\
         \n\
         NOT EXPECTED, AND THIS ROW IS AN ORDINARY HARD CHECK (ADR-0687). This text used to say \
         \"EXPECTED UNTIL THE CNI CHANGES. kindnet enforces no NetworkPolicy\", and then a \
         \"CLEARED BY / DUE\" pair naming yadgarhq/docs ledger 614 and 2026-10-03. The \
         measurement was right and the inference from it was wrong: kindnetd \
         v20260528-9350166c runs a kube-network-policies controller, ledger 614 is WITHDRAWN, \
         and this row has been observed green nineteen times at exactly 18.02s, which is six \
         3000ms drops. So there is no deadline to escalate and nothing to wait for, and a \
         connection that SUCCEEDS is a real regression: read estate-front-egress in \
         yadgarhq/deploy and the target's own ingress policy in yadgar before believing this \
         row is merely stale."
    )
}

/// The failure text must name what was reachable, because that text is the only
/// place a person reading a red run will look.
///
/// This test used to assert that the text carried `deadline_task` and
/// `deadline_date`. Those fields no longer exist, so the assertion is moved to
/// the part of the message that still has a live subject: the addresses the row
/// actually reached, which are the whole diagnostic.
#[test]
fn the_failure_text_names_what_was_reachable() {
    let reached = "iam-db.yadgar.svc.cluster.local:50051 at 10.96.0.7:50051";
    let msg = c18_failure_message(&[reached.to_string()]);
    assert!(msg.contains(reached), "{msg}");
}
