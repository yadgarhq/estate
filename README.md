# estate

The behavioural contract suite and the parity auditor for the yadgar estate.
Implements ADR-0561 and ADR-0562.

Two halves that will share a credential and a runner and nothing else:

- **The behavioural contract suite** — the accepted ADRs in executable form,
  exercised through `https://gateway.yadgar.internal` as a real client. Its
  purpose is to define, after each change, whether the system still works.
- **The parity auditor** — a shared-contract release opens adoption pull requests
  in every consumer, with a nightly sweep as the backstop that should find
  nothing. Stage 4; not built.

**This repository is at stage 1.** What that makes true, and what it does not, is
below. Read it before reading a green run.

## Why it exists

The estate had served zero requests. `yadgar_calls_total` had never been
incremented, so all five KEDA ScaledObjects queried a metric with no values, and
task-db's ADR-0522 read-path enforcement went live having never answered a call.
"No errors in the logs" meant no traffic, not correctness. Every check the estate
owned was a unit or integration test inside one repository; nothing asserted that
the assembled system behaves as the decisions say it does.

## What stage 1 makes true

- The estate serves its first real traffic, and `yadgar_calls_total` acquires
  values.
- Ten smoke rows exist, covering a distinct layer each: edge TLS, login, the
  refusal oracle, attestation, the tool surface, the MCP baseline, the task-db
  read path, cross-user confinement, and the runner's own network confinement.
- ADR-0522's shipped default — an owner reading their own record with the lock
  engaged — is exercised at last.
- A **gateway** roll's verdict is known to describe the rolled code:
  `server/discover` reports the running binary's own release version, and
  `await-roll` polls until it matches the dispatched tag, compared normalised
  because the release pipeline strips the leading `v`.

## What stage 1 does NOT make true

Stated here rather than left to be inferred.

- **The suite cannot run yet.** It needs three things this repository cannot do
  to itself: the `estate-front` ARC runner, the CoreDNS rewrite and stable edge
  Service, and the identity ceremony that writes `ESTATE_PASSWORD`. All three are
  in `MIGRATION_NOTES.md`. Until they exist `smoke.yaml` has no runner and no
  credential, and a dispatched run QUEUES rather than failing — which is easy to
  mistake for a passing one.
- **Nothing sends `module-rolled` yet.** This repository's half of the trigger is
  built; the other half is one step in `yadgarhq/actions`' `ci-release.yaml`.
- **A roll of `iam`, `iam-db`, `task` or `task-db` cannot be confirmed.** Only the
  gateway states its own release through the front door. For the other four,
  `await-roll` prints on the run itself that the verdict may describe the
  previous pods. Stage 3's A-04 replaces that sentence with digest parity for all
  five.
- **C-18 is red.** kindnet enforces no NetworkPolicy, so `runners/`'s policy is
  the specification the row tests rather than something applied. The red carries
  a dated task and the row's own output names it.
- **This repository is not yet visible to the auditor.** `PROTO_VERSION` is what
  makes a repository a consumer the auditor sees, and it is deliberately absent:
  the shared CI's `proto` job reads `PROTO_PATHS` and diffs a vendored `proto/`
  against the pin, so a `PROTO_VERSION` with nothing beside it would fail CI from
  the first commit. It arrives with `estate-annex` at stage 3, which is what
  needs the wire contract.
- **There is no tag, so no release will happen.** A repository with no tag cuts
  none on merge; the version job refuses to compute a bump from no baseline and
  says so.

## The contracts

`crates/front/tests/smoke.rs` holds nine rows; `crates/front/tests/confinement.rs`
holds C-18, which reports as its own check. Each row names the decision it
enforces in its own text, per ADR-0562.

| Row  | Enforces                   | In one line                                                        |
| ---- | -------------------------- | ------------------------------------------------------------------ |
| C-01 | ADR-0507, D72              | A real login answers a token and nothing else                      |
| C-02 | ADR-0507                   | A failed login discloses nothing — status, body and headers        |
| C-03 | ADR-0507 + ADR-0521 method | An unknown username is indistinguishable from a wrong password     |
| C-04 | ADR-0511                   | A bearer token nobody issued authenticates nobody                  |
| C-06 | ADR-0492 (negative), D67   | The tool surface is exactly the declared closed set                |
| C-10 | ADR-0522 (shipped default) | A task round-trips through the whole spine                         |
| C-11 | ADR-0522 + ADR-0521 method | Another user's record reads exactly like no record                 |
| C-13 | D75, MCP 2026-07-28        | The baseline answers as the revision defines, and has no handshake |
| C-14 | ADR-0490 / ADR-0504        | The edge chains to our root, and not to the public web PKI         |
| C-18 | ADR-0562 (self)            | Nothing inside the cluster is reachable from this runner           |

**Every row is `#[ignore]`, and that is not a skip.** They dial the reference
cluster and need a credential; the estate's shared CI has neither. `smoke.yaml`
runs them with `--ignored`, and `cargo test` prints them as ignored everywhere
else, so the subset stays visible.

**Two rows compare captured responses rather than asserting a status twice.**
That is ADR-0521's method: a test asserting only "a refusal happened" passes
against the version where the two refusals differ, which is the oracle that
actually shipped.

`UNOBSERVED.md` lists what this suite does not observe, with the reason and where
each property is held instead. It is part of the deliverable, not an appendix: a
suite whose coverage claim is honest has to write down the gaps.

## Running it

```bash
cargo test                                # the pure rows: reference parsing, pair-equality, helpers
cargo test --test smoke -- --ignored      # the contracts, against the reference cluster
```

From a workstation the name has no DNS record and the edge is not on 443, so:

```bash
ESTATE_EDGE_RESOLVE=127.0.0.1 ESTATE_EDGE_PORT=18443 \
  cargo test --test smoke -- --ignored
```

Those two variables change WHERE the client connects and nothing about what it
trusts: the name in the URL, the SNI and the validated chain are the same either
way. There is no way to turn validation off, deliberately.

## Layout

| Path                   | What                                                                  |
| ---------------------- | --------------------------------------------------------------------- |
| `crates/harness`       | One TLS trust path, byte-level capture, the MCP envelope, the run key |
| `crates/front`         | The contracts, and `await-roll`                                       |
| `reference.toml`       | Every declared observable constant the rows assert against            |
| `ca/root.pem`          | The name-constrained root, public material, committed                 |
| `runners/estate-front` | The ARC values and the NetworkPolicy C-18 tests                       |
| `scripts/enrol.sh`     | The identity ceremony's second half                                   |
| `UNOBSERVED.md`        | What this suite does not observe, and why                             |
| `MIGRATION_NOTES.md`   | Everything stage 1 needs that this repository cannot do to itself     |
