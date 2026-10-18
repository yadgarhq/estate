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
is listed so it is not forgotten. Item 8 is ledger 675 stage 5, and the pull
request that adds the `verdict` job must not merge before it is done.

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
`smoke.yaml` triggers on `workflow_dispatch` and `schedule` only (ledger 675
stage 5 added the poll; stage 7 removed `repository_dispatch`), and neither is
reachable from a fork: a fork's schedules run in the fork, which reaches neither the scale set
nor this repository's environments.

## 3. The CNI change — WITHDRAWN, and there is nothing here for the operator to do

**This item said: "C-18 is red until this lands, by design. kindnet enforces no
NetworkPolicy, so the policy `deploy` applies for item 2 is accepted by the API
server and applied by nothing."** The measurement was right and the inference from
it was wrong. It is quoted rather than deleted, because a reader told only "that
was wrong" re-measures the CNI, finds kindnet, and derives the same false
conclusion.

STILL TRUE: the CNI is kindnet, and there is no Calico, Cilium or Weave. NO LONGER
TRUE: that it enforces nothing. kindnetd `v20260528-9350166c` runs a
`kube-network-policies` controller (ledger 684), and ledger 511 proved ingress
enforcement live twelve times over. C-18 itself has only ever been observed GREEN,
nineteen runs on three separate days, each at exactly `18.02s`, which is six
3000ms drops against the four targets then declared (ledger 751 added three;
about 30.0s now). `reference.toml` lists the run ids.

**The change was kind with `disableDefaultCNI` plus Cilium or Calico, in the nix
repo (ADR-0480). It is not happening.** `yadgarhq/docs` ledger 614 is WITHDRAWN
(docs#51, ADR-0594): the policies this estate ships use only `podSelector`,
`namespaceSelector` and ports, which kindnet enforces, and Cilium is separately
ruled out on measurement — rootless podman puts the kind nodes in a non-initial
user namespace, `/sys/fs/bpf` is `0700 root`, and Cilium mandates
`CAP_SYS_ADMIN`. Calico is left unestablished rather than endorsed.

**The dangling reference is gone, and the decision that cleared it is ADR-0687.**
This item said: "`reference.toml` still carries `deadline_task = "yadgarhq/docs
ledger 614"` with `deadline_date = "2026-10-03"`, and
`the_deadline_is_a_real_date_and_the_task_is_named` is NOT `#[ignore]`d, so on
**2026-10-04 this repository goes red and blocks every merge** on the strength of a
withdrawn row. Clearing that needs a decision — re-date the row, or retire the
deadline machinery and let C-18 be an ordinary hard check." Both halves are now
settled the same way: the three `deadline_*` fields and the test that read them are
DELETED rather than re-dated, because a deadline whose target was withdrawn on
measurement has no commitment left to reschedule, and C-18 is an ordinary hard
check with `continue-on-error` dropped from `smoke.yaml`. There is still nothing
here for the operator to do.

**The FQDN want survives the withdrawal and does not justify a CNI swap.** An
FQDN-aware policy (Cilium) would narrow the runner's GitHub egress from "the
internet on :443, minus this cluster" to GitHub itself. That is a narrowing of a
rule that already works, not a missing capability: rule (d) permits the egress the
suite needs today. The coarseness is stated in the policy file, which lives in
`yadgarhq/deploy` at `infra/estate-front/networkpolicy.yaml`. If it is ever wanted
on its own merits, rootless-podman feasibility becomes the blocking question and
the answer has to come from a real Calico install in a disposable cluster.

## 4. Create the `estate` GitHub environment

Repository settings → Environments → `estate`.

**It must NOT require reviewers.** Smoke runs on a 15-minute poll and the
promise is a verdict within minutes of every settled render; a reviewer-gated
environment turns every render into a job waiting on a human. The control is which workflows may name
the environment — `smoke.yaml` and, later, the other suite workflows — not a
human approving each run.

## 5. The identity ceremony

Creates `estate-suite` and `estate-suite-2` once, and writes their passwords
into the environment from item 4. Repeat it to rotate.

**The two names are declared in `reference.toml` under `[identity]`**, and the
suite reads them from there and from nowhere else (ADR-0569). They were compiled
into `crates/front/src/lib.rs` behind an `ESTATE_USERNAME` variable nothing ever
set. A ceremony that names the accounts otherwise is a one-line edit to
`reference.toml` in the same pull request; the suite has no default to fall back
to, and C-03's positive control is what fails loudly if the file and the accounts
in `iam` disagree.

**The enrolments are minted through the gateway's admin surface** (ADR-0492,
D73): `POST /admin/create-user`, then `POST /admin/issue-enrolment`, on the same
edge the suite dials. This section used to say the admin path did not exist and
the enrolments were minted through `iam`'s gRPC in-cluster; the gateway has
served `/admin/*` since ledger 638 (`gateway/src/http/admin.rs`).

Both calls need an ADMINISTRATOR's bearer token in `Authorization`. The D73
bootstrap token (`x-yadgar-bootstrap-token`) does not do here: on
`create-user` it refuses an ordinary account, and on `issue-enrolment` it admits
only a zero-credential administrator (ADR-0655/0656). The suite identities are
ordinary accounts.

**No secret goes into argv.** argv is readable by every process on the machine
(`ps`, `/proc/<pid>/cmdline`) and lands in shell history. So the admin token is
read with `read -rs` and reaches curl as a header FILE (`-H @<(...)`), and every
body that carries a secret goes on stdin.

Set up once per shell:

```bash
# ADMIN_TOKEN: an administrator's bearer token, from that administrator's own
# POST /auth/login. Paste it at the silent prompt; it is not echoed and does not
# enter history.
read -rs ADMIN_TOKEN

# The edge. Off-cluster (kind) it is on a NodePort, so set ESTATE_EDGE_PORT
# (18443 on kind-yadgar) and ESTATE_EDGE_RESOLVE (the node address) exactly as
# for enrol.sh. The PORT must be in the URL: --resolve changes the address the
# name maps to, never the port curl dials.
HOST=gateway.yadgar.internal
PORT="${ESTATE_EDGE_PORT:-443}"
RESOLVE=()
[ -n "${ESTATE_EDGE_RESOLVE:-}" ] && RESOLVE=(--resolve "${HOST}:${PORT}:${ESTATE_EDGE_RESOLVE}")

# admin <path>: POST the JSON body on stdin to an /admin route.
admin() {
  curl -sS --fail-with-body --cacert ca/root.pem "${RESOLVE[@]}" \
    -H @<(printf 'authorization: Bearer %s' "$ADMIN_TOKEN") \
    -H 'content-type: application/json' \
    -X POST "https://${HOST}:${PORT}$1" --data-binary @-
}
```

**First creation**, for each of the two identities (shown for the first;
repeat with `estate-suite-2`, `USER_ID_2`, `ENROLMENT_SECRET_2`):

```bash
# a. Mint the user. `external_id` IS the login username, so it must equal the
#    name in reference.toml [identity]. Omit `is_admin`: it defaults to false,
#    which is what a suite identity is. The answer is {"user_id": "yadgar:user:..."}.
USER_ID="$(printf '%s' '{"external_id":"estate-suite","display_name":"estate suite"}' \
  | admin /admin/create-user \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["user_id"])')"
echo "$USER_ID"   # not a secret: RECORD IT in the table below

# b. Mint the enrolment. The answer is {"token", "enrolment_id",
#    "revoke_existing_credentials"}; `token` is the single-use secret. It stays
#    in a shell variable and is never printed or written to a file.
RESP="$(printf '{"user_id":"%s"}' "$USER_ID" | admin /admin/issue-enrolment)"
ENROLMENT_SECRET="$(printf '%s' "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
unset RESP

# c. Redeem it, and push the password straight into the environment secret.
printf '%s' "$ENROLMENT_SECRET" | ./scripts/enrol.sh ESTATE_PASSWORD
unset ENROLMENT_SECRET
```

**Rotation skips step a.** `create-user` on a name that exists is refused —
iam-db's `uq_iam_user_blind_index` answers `ALREADY_EXISTS` — and no route
returns an existing account's `user_id`. That is why first creation records it.
Rotation runs step b with the recorded id and `revoke_existing_credentials`,
then step c:

```bash
RESP="$(printf '{"user_id":"%s","revoke_existing_credentials":true}' "$USER_ID" \
  | admin /admin/issue-enrolment)"
# The answer echoes the flag AS APPLIED. Check it says true before redeeming.
printf '%s' "$RESP" | python3 -c 'import json,sys; assert json.load(sys.stdin)["revoke_existing_credentials"] is True, "revoke not applied"'
ENROLMENT_SECRET="$(printf '%s' "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
unset RESP
printf '%s' "$ENROLMENT_SECRET" | ./scripts/enrol.sh ESTATE_PASSWORD
unset ENROLMENT_SECRET
```

`revoke_existing_credentials` must be a JSON boolean. Under ADR-0943 it revokes
EVERY credential the account holds, and it does so AT REDEMPTION — when
`enrol.sh` runs step c — not when the enrolment is issued. Until step c
succeeds, the old password still works; once it does, only the new one does.

**Recorded user ids** (not secrets). Fill them in at first creation, in the
same pull request that records the ceremony.

| Identity         | `user_id`      |
| ---------------- | -------------- |
| `estate-suite`   | _not recorded_ |
| `estate-suite-2` | _not recorded_ |

**BOTH ACCOUNTS ALREADY EXIST, AND THEIR IDS WERE NEVER RECORDED.** They were
minted through `iam`'s gRPC before this table existed. No gateway route answers
an existing account's `user_id`: `/auth/login` answers only `token`, and
`/auth/enrol` answers `token` and `username`. So the first rotation of either
account has no id to start from. Until one is recovered by some other means,
the working path is to mint FRESH accounts under new names through step a,
record their ids here, and change `reference.toml [identity]` in the same pull
request.

`enrol.sh` prints the username and nothing else. The password is generated, sent
to the edge, pushed into the GitHub environment secret, and lost — there is
nothing to recover, which is why rotation is repeating steps b and c.

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

- **`ci-release`'s dispatch step — built, then retired.** `yadgarhq/actions`'
  `ci-release.yaml` sent `repository_dispatch` `module-rolled` to this repository
  on every release. Since ADR-0786 a release moves nothing in the cluster, so
  every such run was red with no verdict (ledger 1376). Ledger 675 stage 7
  (ledger 1487) deleted the sender, then this repository's trigger and
  `await-roll`. The settled-state poll is the only automatic trigger.
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
  `estate-front` is a stated attack surface. This sentence used to continue "whose
  NetworkPolicy today enforces nothing (item 3)"; that inference was wrong, and
  removing it does not weaken the rule. ADR-0563 rejected relying on the policy on
  a ground the CNI never touched: an egress policy does not stop a process reading
  a secret out of its own environment and exfiltrating it through an allowed path,
  and rule (d) of that policy permits the whole internet on :443. Putting an
  organisation-wide write credential inside that blast radius makes the auditor the
  softest way into every repository the
  auditor exists to protect. ADR-0563 decides this: a workflow that reads the
  App's private key runs on a GitHub-hosted runner, and no job on a self-hosted
  runner ever receives it. `estate-front` is a valid label in
  `.github/actionlint.yaml` and actionlint will accept it on these two
  workflows — nothing mechanical stops the mistake, which is why it is written
  in both places.

## 8. The `verdict-reader` environment and its read-only token — **DONE (setup only; the gate cannot pass yet)**

Ledger 675 stage 5 (`plans/settled-state-smoke-gate.md` in `yadgarhq/docs`,
ADR-0840, ADR-0844). `smoke.yaml`'s `verdict` job reads argocd-verify's
`settled-verdict` artifacts with a token held in a dedicated environment.

**Order matters: create the environment BEFORE the pull request merges.** GitHub
auto-creates an environment that a merged workflow names, with no deployment
branch policy, and the token would then land in an unprotected environment. The
token exists since 2026-10-08. Until argocd-verify ships `settled.yaml` (ledger
675 stage 3) there is no `settled-verdict` artifact, so every `verdict` run
ends red with "no verdict for epoch … past the gate's deadline" and the rows
do not run. That red is expected and is not a token fault.

**Observed real-token run.** Run `37821940983` (`token_probe=real`,
2026-10-08T18:08Z), `verdict` job: "##[error]no verdict for epoch
1ce5e6b0…-aa1a2998… past the gate's deadline (2026-10-03T10:35:48+00:00); the
gate and estate may disagree on A".

1. Repository settings → Environments → **`verdict-reader`**. Deployment
   branches and tags: **Selected branches and tags**, one branch rule, `main`,
   no tag rule. Not "protected branches only": estate's protection is a ruleset,
   and GitHub's reading of "protected" is not something to rely on. No required
   reviewers (the poll runs unattended).
2. A **fine-grained token** scoped to the single repository
   `yadgarhq/argocd-verify`: **Actions: read** and **Metadata: read**, nothing
   else. Record its expiry date here when it is minted, so its first expiry is
   expected rather than discovered. **Minted 2026-10-08 (operator-reported).
   Expires 2027-10-08** (365-day fine-grained token lifetime, operator-reported;
   org policy refuses a fine-grained PAT lifetime over 366 days). **Rotate by
   2027-09-08** — repeat steps 2 through 4 below, then run the real-token
   check:

   ```bash
   gh workflow run smoke.yaml --repo yadgarhq/estate --ref main -f token_probe=real
   ```

   Confirm the `verdict` job's error names no 401, 403 or 404 (the two red
   checks further down this section never send this token). ADR-0844 states
   its real reach: Actions: read
   cannot be narrowed to one artifact, so it also reads `verify.yaml`'s snapshots
   and run logs (kind-yadgar object names, uids, Secret NAMES — never Secret
   data).

3. Store it as the environment secret **`ARGOCD_VERIFY_READ_TOKEN`** in
   `verdict-reader`, entered on stdin, never in argv:

   ```bash
   gh secret set ARGOCD_VERIFY_READ_TOKEN --repo yadgarhq/estate --env verdict-reader
   ```

4. Read the policy back:

   ```bash
   gh api repos/yadgarhq/estate/environments/verdict-reader \
     --jq '.deployment_branch_policy'
   gh api repos/yadgarhq/estate/environments/verdict-reader/deployment-branch-policies \
     --jq '[.branch_policies[] | {name, type}]'
   ```

   Want `{"protected_branches":false,"custom_branch_policies":true}` and exactly
   `[{"name":"main","type":"branch"}]`.

**After the merge, the two live red checks** (ADR-0793; the decision logic is
also tested in `scripts/tests/test_verdict_decide.py`):

```bash
gh workflow run smoke.yaml --repo yadgarhq/estate --ref main -f token_probe=own-github-token
gh workflow run smoke.yaml --repo yadgarhq/estate --ref main -f token_probe=bogus
```

The first must end red at the `verdict` job naming **404**, the second naming
**401**; neither may say "waiting".

**Run 2026-10-08, both red as required.** `token_probe=own-github-token` is
run `37820004035`; it failed at the `verdict` job: "argocd-verify answered
404 … This is a refusal, not 'waiting'." `token_probe=bogus` is run
`37820019653`; it failed at the `verdict` job: "argocd-verify answered 401
…".

**Acceptance item 3.** The first `repository_dispatch` after the merge, run
`37810043332`, skipped `verdict` and ran `await-roll` in `smoke` (red, as
every module-rolled dispatch is until stage 7).

**Observation, not a cause claim.** No `schedule` run of `smoke.yaml` had
fired as of 2026-10-08 ~18:10Z (`gh api
repos/yadgarhq/estate/actions/workflows/smoke.yaml/runs?event=schedule --jq
'.total_count'` → `0`).

**The 60-day schedule rule.** GitHub disables a public repository's scheduled
workflows after 60 days without repository activity. GitHub does not define
'repository activity'; workflow runs are reported not to count, so the
conservative proxy is the age of the newest commit on estate `main`. Dependabot's bumps are
the only regular commits here, so a quiet stretch is plausible. The guard
belongs in argocd-verify's `settled.yaml` (stage 3), and it must fail on the age
of estate `main`'s newest commit past 45 days — not on the age of the newest
`smoke.yaml` run, which stays near zero until the day GitHub disables the
schedule (GitHub emails on a failed scheduled run). The only recovery is to
re-enable the workflow by hand:

```bash
gh workflow enable smoke.yaml --repo yadgarhq/estate
```

**Rollback.** Revert the pull request; the `repository_dispatch` path never
changed. Delete the token in GitHub settings and the environment with
`gh api -X DELETE repos/yadgarhq/estate/environments/verdict-reader`.
