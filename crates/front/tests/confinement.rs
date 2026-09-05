//! C-18 — the front-door runner's confinement (ADR-0562, self).
//!
//! **THIS ROW IS RED AT BIRTH AND THE RED IS THE HONEST ALARM.** The cluster's
//! CNI is kindnet, which enforces no NetworkPolicy. The policies in `runners/`
//! are therefore the SPECIFICATION this row tests rather than something the
//! network applies, and until the CNI changes this row fails. That is correct
//! behaviour for a suite whose purpose is to say what is true.
//!
//! **THE RED CARRIES A DEADLINE, AND THAT IS NOT DECORATION.** ADR-0561's own
//! doctrine is that a transient gap is a task with a deadline, never a recorded
//! state; an indefinite red is that forbidden recorded state one level down, and
//! it is what trains people to ignore red. So the failure output names the task
//! that will clear it and the date it should have, both declared in
//! `reference.toml`. A row nobody can date is a row nobody will fix.
//!
//! **IT IS ITS OWN FILE AND ITS OWN CHECK.** `smoke.yaml` runs this target in a
//! separate step so a standing red does not swallow the verdict of the nine rows
//! that are not red by design. That separation is itself a compromise — it may
//! blunt the alarm — and the deadline is the half worth defending.
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

    anyhow::ensure!(
        reachable.is_empty(),
        "{}",
        red_at_birth_message(&reference, &reachable)
    );
    Ok(())
}

/// The failure text, which must name the thing that will clear it and the date
/// it should have.
fn red_at_birth_message(reference: &Reference, reachable: &[String]) -> String {
    let c = &reference.confinement;
    format!(
        "C-18 IS RED: the front-door runner opened a TCP connection to {reachable:?}. \
         \"Through the front door\" is not enforced by the network, so any suite bug or \
         compromised test dependency can bypass the edge while every other row reports green.\n\
         \n\
         EXPECTED UNTIL THE CNI CHANGES. kindnet enforces no NetworkPolicy, so the policies in \
         runners/ are the specification this row tests rather than something applied.\n\
         \n\
         CLEARED BY: {} — {}\n\
         DUE:        {}\n\
         \n\
         If today is past that date, the gap has become a recorded state, which ADR-0561 forbids. \
         Escalate the task rather than muting the row.",
        c.deadline_task, c.deadline_summary, c.deadline_date
    )
}

/// The deadline must be a real calendar day that is NOT ALREADY PAST, and the
/// task that clears the red must be named.
///
/// Runs everywhere, needs no cluster. A `deadline_date` of `TBD`, or one left
/// behind by a year, turns the row's whole justification — "a gap with a
/// deadline, never a recorded state" — back into the recorded state it exists
/// to avoid, and nothing would say so. An earlier revision of this test asserted
/// only the ISO shape, so the promise in this comment was made by the comment
/// and kept by nothing.
///
/// **THIS TEST IS NOT `#[ignore]`, WHICH IS THE WHOLE MECHANISM AND ALSO THE
/// WHOLE COST.** It runs in the estate's ordinary `cargo test`, so on the day
/// after `deadline_date` this repository goes red and blocks merges that have
/// nothing to do with C-18. That is the alarm working: the answer is to clear
/// the task or to re-date it deliberately in `reference.toml`, both of which are
/// reviewed edits. Muting it is the recorded state ADR-0561 forbids.
///
/// "Not already past" rather than "strictly future": on the due date itself the
/// task is due, not overdue, and `red_at_birth_message` says "if today is past
/// that date". The two statements have to agree.
#[test]
fn the_deadline_is_a_real_date_and_the_task_is_named() {
    let reference = Reference::load().expect("reference.toml parses");
    let c = &reference.confinement;
    let deadline = parse_iso_date(&c.deadline_date)
        .unwrap_or_else(|e| panic!("deadline_date {:?}: {e}", c.deadline_date));
    let today = today_utc();
    assert!(
        deadline >= today,
        "deadline_date {} HAS PASSED. C-18's red was justified as a gap with a deadline rather \
         than a recorded state, and that justification expired with the date. Clear \
         `{}` — {} — or re-date this deliberately in reference.toml. Muting the row is the \
         recorded state ADR-0561 forbids.",
        c.deadline_date,
        c.deadline_task,
        c.deadline_summary
    );
    assert!(
        !c.deadline_task.trim().is_empty() && !c.deadline_summary.trim().is_empty(),
        "the red must name the task that clears it"
    );
}

/// An ISO `yyyy-mm-dd` day as a count of days since the Unix epoch.
///
/// **NO DATE CRATE, DELIBERATELY.** This is the only date arithmetic in the
/// repository and it is eleven lines; a dependency added for it would enter
/// `Cargo.lock` and `cargo deny`'s licence and advisory surface to answer one
/// question. The conversion is Howard Hinnant's `days_from_civil`, which is
/// exact for every proleptic Gregorian date and needs no table.
///
/// The month and day ranges are checked BEFORE the conversion, because the
/// conversion accepts month 13 and day 45 without complaint — and a placeholder
/// is exactly the kind of value that would be out of range.
fn parse_iso_date(text: &str) -> Result<i64, String> {
    let parts: Vec<&str> = text.split('-').collect();
    if parts.len() != 3 || parts.iter().any(|p| !p.chars().all(|c| c.is_ascii_digit())) {
        return Err("must be ISO yyyy-mm-dd, digits and dashes only".into());
    }
    if parts[0].len() != 4 || parts[1].len() != 2 || parts[2].len() != 2 {
        return Err("must be ISO yyyy-mm-dd, zero-padded".into());
    }
    let num = |s: &str| s.parse::<i64>().map_err(|e| e.to_string());
    let (y, m, d) = (num(parts[0])?, num(parts[1])?, num(parts[2])?);
    if !(1..=12).contains(&m) {
        return Err(format!("month {m} is not a month"));
    }
    if !(1..=31).contains(&d) {
        return Err(format!("day {d} is not a day"));
    }
    Ok(days_from_civil(y, m, d))
}

/// Howard Hinnant's `days_from_civil`: a proleptic Gregorian date to a day
/// number, with the epoch at 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Today, as the same day count. UTC, because the deadline is a date in a
/// document rather than an instant, and a local zone would make the test's
/// verdict depend on where it ran.
fn today_utc() -> i64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_secs();
    (secs / 86_400) as i64
}

/// The failure text must carry the deadline, because that text is the only place
/// a person reading a red run will look.
#[test]
fn the_failure_text_names_the_task_and_the_date() {
    let reference = Reference::load().expect("reference.toml parses");
    let msg = red_at_birth_message(&reference, &["iam-db:50051".to_string()]);
    assert!(msg.contains(&reference.confinement.deadline_task), "{msg}");
    assert!(msg.contains(&reference.confinement.deadline_date), "{msg}");
}

/// The date arithmetic the deadline guard rests on, asserted rather than
/// assumed. A guard whose comparison is wrong is worse than no guard: it would
/// either never fire, or fire on a date nobody can explain.
#[test]
fn the_date_arithmetic_is_correct() {
    assert_eq!(days_from_civil(1970, 1, 1), 0, "the epoch is day zero");
    assert_eq!(days_from_civil(1970, 1, 2), 1);
    assert_eq!(days_from_civil(1969, 12, 31), -1);
    // 2000 is a leap year (divisible by 400) and 1900 is not (by 100).
    assert_eq!(
        days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28),
        2,
        "2000-02-29 exists"
    );
    assert_eq!(
        days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28),
        1,
        "1900-02-29 does not exist"
    );
    assert_eq!(days_from_civil(2026, 10, 3), 20_729);
    assert!(days_from_civil(2026, 10, 3) > days_from_civil(2026, 9, 5));
}

/// A placeholder must be refused by the parser rather than silently accepted as
/// a date. `TBD` is the value this whole guard exists to catch.
#[test]
fn a_placeholder_deadline_is_not_a_date() {
    for bad in [
        "TBD",
        "",
        "2026-10",
        "2026-13-01",
        "2026-10-45",
        "2026-1-3",
        "soon",
    ] {
        assert!(
            parse_iso_date(bad).is_err(),
            "{bad:?} was accepted as a deadline"
        );
    }
    assert!(parse_iso_date("2026-10-03").is_ok());
}
