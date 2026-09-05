# Migration notes

Everything stage 1 needs that this repository cannot do to itself. Each item is
a cluster change, an organisation setting, or a credential ceremony.

**Item 6 HAS been run** (2026-09-05, verified against the live repository).
**Item 1 needs nothing run at all** — it is declared in `yadgarhq/deploy` and
applied by Argo. Items 2 to 5 have not been done.

**Until items 2 to 5 are done, `smoke.yaml` has no runner and no credential.
It will queue rather than fail.** That is stated in the README as well, because
a queued workflow is easy to mistake for a passing one.

Ordered by dependency. Items 1 and 2 are cluster changes and are declared in
`yadgarhq/deploy`; what is left of them for a person is in that repository's own
`MIGRATION_NOTES.md`. Item 3 lives in the `nix` repository. Item 4 is a GitHub
setting, item 5 is the credential ceremony and needs 1 to 4, and item 6 is
repository settings and is independent of all of them. Item 7 is not stage 1 and
is listed so it is not forgotten.

---

## 1. Resolving `gateway.yadgar.internal` in-cluster — **NOTHING TO RUN HERE**

The suite dials the external NAME so that SNI, the leaf and the name-constrained
chain are the ones a real client validates. Only RESOLUTION is redirected; trust
never is.

**This is declared in `yadgarhq/deploy` and applied by Argo**, so there is no
step for a person. `infra/estate-front/edge-service.yaml` creates `yadgar-edge`,
a stable ClusterIP Service on a pinned address selecting the Envoy proxy pods by
label (the live Service `envoy-yadgar-edge-a2648de2` is hash-suffixed and may
not be depended on), serving `port: 443` with `targetPort: 10443` — the Envoy
pods listen on 10443. `infra/estate-front-runner.yaml` gives the runner pod a
`hostAliases` entry mapping the name to that address.

**It is deliberately NOT the CoreDNS rewrite this document used to ask for.**
That ConfigMap is written by kubeadm when kind creates the cluster, so an
Argo-managed copy is two writers of one object — ADR-0480's stated failure mode.
The reasoning, and the exact `rewrite` line should a second in-cluster consumer
ever need the name, are in `deploy`'s own `MIGRATION_NOTES.md`.

**What it does not cover:** the name resolves in the runner pod and nowhere else
in the cluster. Stage 3's `estate-annex` scale set gets the same entry.

## 2. Install the `estate-front` runner scale set — **IN `yadgarhq/deploy`**

The values and the NetworkPolicy used to live in `runners/estate-front/` here.
They do not any more: one spec in two repositories drifts, and the copy that
drifts is the one not being applied. `deploy` holds the only copy —
`infra/arc.yaml` (the controller), `infra/estate-front-app.yaml` plus
`infra/estate-front/` (the policy and the edge address), and
`infra/estate-front-runner.yaml` (the scale set). Argo applies all three.

**Two things Argo cannot do, both in `deploy`'s `MIGRATION_NOTES.md`:**

- **Build and push the runner image.** A purpose-built image rather than a
  `rustup` step at job time — `smoke.yaml`'s `dtolnay/rust-toolchain` step drives
  `rustup`, which the stock ARC image does not carry, and a `curl | sh` inside
  the pod holding this repository's `ESTATE_PASSWORD` is the opposite of what
  D61 asks for. `deploy` carries the Containerfile; it pins
  `rust-toolchain.toml`'s channel, so bumping that channel means rebuilding it.
  Pushing it is not the end of that step: a package created by a first push to
  GHCR is private, the runner pod carries no pull credential, and a private
  image is `ImagePullBackOff` with a 401. `deploy`'s notes carry the login, the
  visibility change and an anonymous-pull check.
- **Create the `estate-runner-github` Secret**, holding the `yadgarhq-bot` App.

**THERE IS NO RUNNER GROUP, AND THERE CANNOT BE.** This document used to require
an organisation runner group named `estate` restricted to this repository.
Measured 2026-09-05: `yadgarhq` is on the **free** plan, and
`GET /orgs/yadgarhq/actions/runner-groups` returns exactly one group, `Default`
(`visibility: all`). Custom runner groups are a Team or Enterprise feature. What
replaces it is stronger: the scale set registers against
`https://github.com/yadgarhq/estate`, so the runners are repository runners of
this repository and no other repository's workflow can target them — enforced by
GitHub rather than by a setting somebody has to keep right.

Likewise, the organisation setting this document named — fork pull-request
workflows must not run on self-hosted runners — governs PRIVATE repositories,
and this one is public. The public equivalent is the fork pull-request approval
policy, and it is **already at its strictest here — there is nothing to set**.
Measured 2026-09-05, `yadgarhq/estate` reads `all_external_contributors`, as do
all fifteen public repositories in the organisation:

```bash
gh api /repos/yadgarhq/estate/actions/permissions/fork-pr-contributor-approval
```

It is a per-repository value rather than an inherited one, so it is not
self-maintaining: the organisation default still reads
`first_time_contributors`, and what keeps a new repository correct is `apply.sh`
in `yadgarhq/docs`, which sets it at creation. This is defence in depth anyway:
`smoke.yaml` triggers on `repository_dispatch` and `workflow_dispatch` only, and
neither is reachable from a fork.

## 3. The CNI change — the dated task C-18 names

**C-18 is red until this lands, by design.** kindnet enforces no NetworkPolicy,
so the policy `deploy` applies for item 2 is accepted by the API server and
applied by nothing.

The change is kind with `disableDefaultCNI` plus Cilium or Calico, and it lives
in the **nix repo** (ADR-0480), outside this repository's write scope.

Filed as a dated task so the red is a gap with a deadline rather than a recorded
state: **`yadgarhq/docs` ledger 614, due 2026-10-03.** C-18's own failure output
prints both. If today is past that date, escalate the task rather than muting the
row.

Worth deciding together with the CNI: an FQDN-aware policy (Cilium) would narrow
the runner's GitHub egress from "the internet on :443, minus this cluster" to
GitHub itself. That coarseness is stated in the policy file, which now lives in
`yadgarhq/deploy` at `infra/estate-front/networkpolicy.yaml`.

## 4. Create the `estate` GitHub environment

Repository settings → Environments → `estate`.

**It must NOT require reviewers.** Smoke runs on `module-rolled` and the promise
is a verdict within minutes of every roll; a reviewer-gated environment turns
every roll into a job waiting on a human. The control is which workflows may name
the environment — `smoke.yaml` and, later, the other suite workflows — not a
human approving each run.

## 5. The identity ceremony

Creates `estate-suite` and `estate-suite-2` once, and writes their passwords
into the environment from item 4. Repeat it to rotate.

**ADR-0492's admin path does not exist**, so the enrolments cannot be minted
through a front door. They are minted through `iam`'s gRPC, which is an
in-cluster act — an enumerated exception, done deliberately and logged.

For each of the two identities:

```bash
# a. Mint the user and an enrolment, in-cluster, via iam's gRPC.
#    CreateUser, then IssueEnrolment. Capture the enrolment secret; do not
#    write it to a file.
#
# b. Redeem it, and push the password straight into the environment secret.
#    The secret arrives on stdin, never in argv: argv is visible in `ps` and
#    lands in shell history.
printf '%s' "$ENROLMENT_SECRET" | ./scripts/enrol.sh ESTATE_PASSWORD
printf '%s' "$ENROLMENT_SECRET_2" | ./scripts/enrol.sh ESTATE_PASSWORD_2
```

The script prints the username and nothing else. The password is generated, sent
to the edge, pushed into the GitHub environment secret, and lost — there is
nothing to recover, which is why rotation is repeating the ceremony.

## 6. Apply the standard repository settings and rulesets — **DONE**

From `yadgarhq/docs/github`, with a token acting as an organisation owner:

```bash
./apply.sh estate
```

This sets squash-only merging with `PR_TITLE` / `PR_BODY`, delete-on-merge, the
`main` ruleset requiring `ci / passed`, and the `release-tags` ruleset.

**Already applied.** Verified 2026-09-05 against the live repository: it is
public, `allow_squash_merge` is the only merge method enabled,
`squash_merge_commit_title` is `PR_TITLE` and `squash_merge_commit_message` is
`PR_BODY`, `delete_branch_on_merge` is true, and both the `main` and
`release-tags` rulesets exist and are `active`. Re-run `./apply.sh estate` only
to restore these after a settings change.

## 7. Not stage 1, and named here so it is not forgotten

- **`ci-release`'s dispatch step.** The trigger half of "a verdict after every
  roll" lives in `yadgarhq/actions`: `ci-release.yaml`'s deployment job gains one
  step that sends `repository_dispatch` to `yadgarhq/estate`, event
  `module-rolled`, payload `{module, tag, digest}`. This repository's half — the
  trigger — is built and waiting. Nothing sends the event yet.
- **The GitHub App permissions stage 4 needs — all of them are held. NOTHING TO
  DO.** The App is **`yadgarhq-bot`** (app_id 4814165, installation 158692002,
  installed organisation-wide). It was named `yadgarhq-tagger` when this was
  designed and the id did not change; ADR-0561 records the old name because an
  ADR records what was true when it was decided.

  Measured 2026-09-05 — `gh api /orgs/yadgarhq/installations` — it holds
  `actions: write`, `administration: write`, `contents: write`,
  `issues: write`, `metadata: read`,
  `organization_self_hosted_runners: write`, `pull_requests: write` and
  `workflows: write`.

  All three the design asked for are in that set: `pull_requests: write`, which
  is what lets the auditor open an adoption pull request at all;
  `workflows: write`, without which GitHub refuses a push from an App that
  touches a file under `.github/workflows/` and surface 3 would be dead on
  arrival rather than weak; and `issues: write`, which is the sweep's alarm
  issue, a sweep that finds drift and cannot say so being a green cron. Earlier
  revisions of this document listed three, then two, as outstanding. None are.

  **`administration: write` is the one nobody asked for**, and it is here
  because the `estate-front` scale set registers against a REPOSITORY rather
  than the organisation, which is what GitHub charges for that. The installation
  is organisation-wide (`repository_selection: "all"`), so it reaches every
  repository in `yadgarhq` — settings, branch protection, collaborators,
  deletion. ADR-0563 is what keeps that tolerable: no job on a self-hosted
  runner ever receives this key. See the next item.

- **`adopt.yaml` and `sweep.yaml` MUST declare `runs-on: ubuntu-latest`.** They
  are stage 4's workflows and they are written **in this repository**, so this
  is where the warning belongs. They mint installation tokens from the App
  above, which is organisation-wide write across every repository in the estate.
  `estate-front` is a stated attack surface whose NetworkPolicy today enforces
  nothing (item 3). Putting an organisation-wide write credential inside that
  blast radius makes the auditor the softest way into every repository the
  auditor exists to protect. ADR-0563 decides this: a workflow that reads the
  App's private key runs on a GitHub-hosted runner, and no job on a self-hosted
  runner ever receives it. `estate-front` is a valid label in
  `.github/actionlint.yaml` and actionlint will accept it on these two
  workflows — nothing mechanical stops the mistake, which is why it is written
  in both places.
