# Decisions this suite does NOT observe

ADR-0562: a decision whose behaviour cannot be observed from the front door is
**stated as such**, never tested by a shortcut. This file is that statement. It
is linked from every run's output, so the list is visible on every run rather
than filed once and forgotten.

A shortcut — reaching past the edge to assert something the edge cannot show —
would produce a green suite that proves less than it appears to. That is the
failure this whole repository exists to remove one level up, so it is not
allowed to reappear inside it.

## Genuinely unobservable without destruction

One line each, with the reason and where the property is held instead.

- **ADR-0491, crypto at rest** (AES-GCM naming, blind index, Argon2id):
  database-internal. The front door sees only that login works. Held by iam-db's
  own tests.
- **ADR-0513, idempotency serialisation**: the gateway mints the idempotency key
  per inbound request, so no caller can replay a key through the front door at
  all. The concurrency property is held by the barrier tests ADR-0513 itself
  mandates.
- **ADR-0523, rotation exit-on-change**: observable only by rewriting a live
  Secret — a mutation this suite must not perform. The annex (stage 3, row A-03)
  observes the gauges the ADR itself designates as the proxy.
- **ADR-0532 / ADR-0555, lazy dial and UNAVAILABLE-not-crashloop**: requires
  killing a service mid-run. Game-day material, not CI.
- **ADR-0517 zero-manual-step first sync**, and **ADR-0518 refuse-to-boot on an
  absent data-bearing key**: both are properties of a FRESH cluster. ADR-0517's
  own acceptance test is `git clone && argocd sync` on an empty cluster, and
  ADR-0518's is a pod that will not start when a Secret is missing. Neither can
  be observed without destroying the reference deployment or standing up a
  second one. Game-day material, and the game day for these two is a scratch
  cluster rather than this one.
- **ADR-0534, `unverified_actor` audit semantics**: needs an admin surface
  (absent) and audit-store reads (absent).
- **ADR-0507's 503 arm, cause coverage**: forcing it means taking `iam` down.
  The mapping is pinned by the gateway's exhaustive `login_answer` /
  `enrol_answer` unit tests; this suite asserts only the reachable arms.
- **ADR-0491's audit half, which is D72's other half** — a source address
  recorded on every authentication event including failures. Not merely
  untested: **unimplemented estate-wide.** There is no audit store to read, and
  `YADGAR_TRUSTED_PROXY_HOPS` is empty, so there is no trusted proxy declaration
  from which a source address could be believed. Listed here rather than left
  out, because it is the largest thing this suite does not cover and the claim
  being made is that the coverage is honest. It becomes testable when the audit
  store lands, and its contract is written then.
- **ADR-0522's exception arm.** C-10 and C-11 exercise only the SHIPPED DEFAULT
  — the organisation's value read with the lock ENGAGED. The arm that makes the
  setting a setting (lock clear, a team override changing what a front-door read
  returns) is untested here, and stage 3's A-05 does not close it: A-05
  exercises the RPC's shape, not the read consequence. Testing it means clearing
  the ORGANISATION-level lock, which is global shared state on the reference
  cluster and which ADR-0522 defines as having no cleared state to restore to —
  the org value cannot be cleared at all, only replaced. So this arm is not a row
  this suite can own. ADR-0522's own "a test must cover all four combinations of
  lock and override" is owed by task-db's and iam's unit tests, and it is owed
  there rather than here.
- **ADR-0525's broker-account rule.** The property is that a subscriber reports
  itself consuming only once its subscription is acknowledged, and the ADR
  records that drift in the broker's allow-list surfaces "solely through the new
  error log". With no log shipper in the namespace (ADR-0557), there is nothing
  for the front door or the annex to read. Stated, not tested, and stated with
  the reason it is not.

## Blocked on missing surface

**ADR-0492's admin path does not exist.** The admin API is described as "served
by the gateway on a separate path", and that path is not built. So
"admin creates the account" has no front door, and this is recorded as a
dependency rather than silently absorbed.

The day `/admin` lands, C-06 goes red — it asserts closed-set equality on the
tool surface — and **that red is the trigger to write the admin contracts**:
bootstrap-token scope, `is_admin` refusal for non-admins, and `IssueEnrolment`
idempotency-key refusal per ADR-0519's letter.

## Not yet built, rather than unobservable

Distinct from everything above: these are observable, and the rows are designed.
They are not here because their stage is not here.

- Stage 2: C-05, C-07, C-12, C-15, C-16, C-17, C-19 — the caller-written identity
  header, the administrative probes, the closure rule, the response-time floor,
  the rate limiter and the forged-attribution defeat, and the real-client pass.
- Stage 3: the whole in-cluster annex (A-01..A-10), the per-run ephemeral
  identity, and with it C-08 and C-09 — the enrolment and replay contracts,
  which spend a single-use secret and therefore need that identity.
- Stage 3 also retires stage 1's unconfirmed-roll sentence: A-04 compares the
  deployed image digest to the dispatched one for all five modules, where today
  only the gateway can be confirmed from the front door.
- Stage 4: the parity auditor. Until it exists, `PROTO_VERSION` is deliberately
  absent from this repository and **estate is not yet visible to the auditor as
  a consumer** — see the README.
