# Migration notes

Everything stage 1 needs that this repository cannot do to itself. Each item is
a cluster change, an organisation setting, or a credential ceremony, and all
three belong to a person.

**Item 6 HAS been run** (2026-09-05, verified against the live repository); items
1 to 5 have not. An earlier revision of this file said nothing here had been
run, which was already untrue when it was written.

**Until items 1 to 5 are done, `smoke.yaml` has no runner and no credential.
It will queue rather than fail.** That is stated in the README as well, because
a queued workflow is easy to mistake for a passing one.

Ordered by dependency. Items 1, 2 and 3 are cluster changes — 3 lives in the
`nix` repository rather than in `deploy`. Item 4 is a GitHub setting, item 5 is
the credential ceremony and needs 1 to 4, and item 6 is repository settings and
is independent of all of them. Item 7 is not stage 1 and is listed so it is not
forgotten.

---

## 1. Give `gateway.yadgar.internal` a stable in-cluster address

The suite must dial the external NAME so that SNI, the leaf and the
name-constrained chain are the ones a real client validates. Only RESOLUTION is
redirected; trust never is.

The live Envoy Service is `envoy-yadgar-edge-a2648de2` — the suffix is a hash
that changes when the Gateway is recreated, so nothing may depend on it.

Add, in the repository that owns the cluster (`deploy`, applied through
`argocd`):

- a stable `ClusterIP` Service `yadgar-edge` in `envoy-gateway-system`, selecting
  the Envoy proxy pods by the labels
  `app.kubernetes.io/name: envoy`,
  `gateway.envoyproxy.io/owning-gateway-name: edge`,
  `gateway.envoyproxy.io/owning-gateway-namespace: yadgar`
  (the same labels `runners/estate-front/networkpolicy.yaml` selects on, and for
  the same reason), serving **`port: 443` with `targetPort: 10443`** — the Envoy
  pods listen on 10443, which is what the live Service already does and what the
  NetworkPolicy's rule (b) has to allow; the reason that port and not 443 is the
  one a policy must name is written down in `networkpolicy.yaml`;
- a CoreDNS rewrite:

  ```
  rewrite name gateway.yadgar.internal yadgar-edge.envoy-gateway-system.svc.cluster.local
  ```

Verify from any pod: `getent hosts gateway.yadgar.internal` resolves, and a TLS
handshake to it validates against `ca/root.pem`.

## 2. Install the `estate-front` runner scale set

`runners/estate-front/` holds the values and the NetworkPolicy. Two things must
exist first, and neither is created by the chart:

- **A runner group named `estate`, restricted to `yadgarhq/estate` only.**
  Organisation settings → Actions → Runner groups. A group visible to the whole
  organisation lets any repository's workflow execute inside this cluster.
- **A runner image carrying a Rust toolchain.** `values.yaml` leaves `image:`
  empty deliberately. The default ARC image has no `rustup`, and
  `smoke.yaml`'s toolchain step then fails with a message about a missing binary
  rather than about a missing image. Build one from `ghcr.io/actions/actions-runner`
  plus rustup, or add the runner to the estate's own `rust-build` base.

Also set, in the organisation's Actions settings: **fork pull-request workflows
must not run on self-hosted runners.** `smoke.yaml` never triggers on
`pull_request`, and this is the second lock on the same door.

Then, the operator runs (this repository never applies it):

```bash
kubectl apply -f runners/estate-front/networkpolicy.yaml
helm install estate-front \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --namespace estate-front \
  --values runners/estate-front/values.yaml
```

`actions-runner-controller` itself must already be installed in the cluster.

## 3. The CNI change — the dated task C-18 names

**C-18 is red until this lands, by design.** kindnet enforces no NetworkPolicy,
so item 2's policy is accepted by the API server and applied by nothing.

The change is kind with `disableDefaultCNI` plus Cilium or Calico, and it lives
in the **nix repo** (ADR-0480), outside this repository's write scope.

Filed as a dated task so the red is a gap with a deadline rather than a recorded
state: **`yadgarhq/docs` ledger 614, due 2026-10-03.** C-18's own failure output
prints both. If today is past that date, escalate the task rather than muting the
row.

Worth deciding together with the CNI: an FQDN-aware policy (Cilium) would narrow
the runner's GitHub egress from "the internet on :443, minus this cluster" to
GitHub itself. That coarseness is stated in the policy file.

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
- **Three GitHub App permissions**, a prerequisite of stage 4 rather than a
  follow-up: the `yadgarhq-tagger` App needs `pull_requests: write` (to open an
  adoption PR at all), `workflows: write` (a push touching a workflow file is
  refused without it, which would make the CI-contract surface dead on arrival)
  and `issues: write` (the sweep's alarm issue; a sweep that finds drift and
  cannot say so is a green cron).
