#!/usr/bin/env python3
"""The ADR-0561 parity auditor: the nightly backstop over the whole estate.

yaadgaar 224 (ledger 784). Two predicates, each a pure function over a
SNAPSHOT — the facts read from GitHub, recorded as JSON — so the tests run on
recorded estates and never on the network:

  P1  PIN PARITY. Every consumer pins the LATEST released tag of every in-org
      shared contract (ADR-0561: latest only, no exceptions file). Three pin
      surfaces:
        - `PROTO_VERSION`, against `proto`'s greatest tag;
        - every `[[package]]` in `Cargo.lock` whose `source` is a git URL in the
          organisation, keyed on the SOURCE-URL `?tag=` — never on the crate's
          Cargo `version`, which can lag its tag. `Cargo.lock` rather than
          `Cargo.toml` because it covers workspace members and transitive pins.
          A git source with no `tag=` (a `rev=` or `branch=`) is a finding;
        - the `rev:` of the `https://github.com/<owner>/actions` block in
          `.pre-commit-config.yaml`.
      P1 also asks who ADVANCES those pins (ruling, Max 2026-10-30): a
      repository with any in-org git package in `Cargo.lock` must carry
      `.github/workflows/repin.yaml` with a job that calls
      `<owner>/actions/.github/workflows/repin.yaml@`. Without that caller
      nothing proposes the adoption, and the pin stays behind until a human
      notices.
  P2  HOOK-SET CONFORMANCE BY CLASS (ruling, Max 2026-10-29). Classes are
      deployable, crate, chart, infra and docs. A hook id is REQUIRED in a class
      when at least 80% of that class's repositories carry it; a repository
      missing a required hook fails. Hook ids are counted across EVERY block of
      `.pre-commit-config.yaml` (pre-commit-hooks, actions, local), because the
      task names local hooks (`pytest-scripts`, `cargo-doc-*`) among the drift.

  P3  RELEASE APP SECRETS (yaadgaar 324, option C; ruling, Max 2026-10-29 and
      2026-10-30). Every repository that USES `RELEASE_APP_CLIENT_ID` or
      `RELEASE_APP_PRIVATE_KEY` must be able to see it, as an organisation
      secret visible to the repository or as a repository secret. Who uses them
      is read from each repository's own `.github/workflows/*.y*ml`, never
      listed here: a `secrets.<name>` or `secrets['<name>']` reference in a
      value (case-insensitive, as Actions expressions are), or `secrets:
      inherit` handed to a `<owner>/actions` workflow (both names). A comment
      or a `workflow_call` declaration key is not a use. A workflow file that
      does not parse is a finding naming the repository and the file. Visibility is read by
      NAME through the read-only App `yadgarhq-audit`; the API returns no
      values. Every failure to read is a finding, never a skip.

The class of a repository is derived from GitHub topics, in this order
(ruling, Max 2026-10-30):
  1. an EXPLICIT `estate-class-<class>` topic, where `<class>` is one of the
     five ruling classes, names it outright. Several, or an unknown class, is
     a finding. The prefix is deliberately not `yadgar-class-`: that one is
     `classes.json` `topic_prefix` in `yadgarhq/actions`, whose sweep refuses a
     repository with two topics under it;
  2. otherwise the `yadgar-deployable` topic makes it `deployable`;
  3. otherwise its ONE `yadgar-class-<name>` topic is mapped through CLASS_MAP,
     the legacy fallback. Zero or several is a finding.
The topics are mutable by any repository admin; the auditor only reads them.

ENUMERATION matches `yadgarhq/actions` `scripts/sweep.py`: public repositories
only (the workflow's GITHUB_TOKEN cannot read a private one, and a local run
with a wider token must see the same estate), not archived, not a fork, not
disabled, not named in `classes.json` `sweep.exclude`. `classes.json` `exempt`
(the producer `actions`) is exempt from P2 only. The auditor includes ITSELF:
this repository is a consumer like any other (ADR-0561).

Commands:

    audit.py gather --owner O --out snapshot.json      read GitHub, write facts
    audit.py needs   --owner O --out needs.json --outputs PATH   who uses the release App
    audit.py secrets --owner O --needs needs.json --outputs PATH  what each of them sees
    audit.py check   --snapshot snapshot.json [--secrets doc.json] [--summary PATH] [--outputs PATH]

`needs` reads public files with the run's own token and hands the names on
(comma-separated, for the App token's `repositories:`); it refuses an empty
list, because an empty `repositories:` beside `owner:` mints for every
repository. `secrets` reads the two secret listings per repository with the
App token and hands `{"owner", "needs", "visibility"}` on as one JSON line.
`check --secrets` judges P3 from that document; an empty or broken one is a
P3 finding, so a failed or skipped `secrets` job reads RED, not green.
`--secrets-result` (the job's `result`) names why the document is empty.

`check` writes a Markdown report and exits 1 when any predicate fails.
Without `--secrets` (a local run) P3 is reported as not run. With
`--outputs` (the step's $GITHUB_OUTPUT) it also hands `verdict` (green or red)
and `report` to the workflow's `route` job, which keeps one GitHub issue in
step with the result through `scripts/audit_issue.py`. Every command here reads
only: `gather`, `needs` and `secrets` issue GET requests through `gh api` and
nothing else.

Tests: python3 -m pytest scripts/tests -q
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import subprocess
import sys
import tomllib
import urllib.parse

import yaml

DEPLOYABLE_TOPIC = "yadgar-deployable"
CLASS_PREFIX = "yadgar-class-"
EXPLICIT_PREFIX = "estate-class-"
# The LEGACY fallback: `yadgar-class-*` topic -> ruling class, consulted only
# when no `estate-class-*` topic names the class outright. `yadgar-deployable`
# is checked first, so `service` and `seeder`'s `rust-helm` both land in
# `deployable`. THREE FITS ARE LOOSE, which is why the explicit topics exist:
# `base` holds argocd and proto (and the private docs), `rust-app` holds estate
# and yadgar, and no `yadgar-class-*` topic means docs.
CLASS_MAP = {
    "service": "deployable",
    "rust-lib": "crate",
    "rust-helm": "crate",
    "chart": "chart",
    "base": "infra",
    "verify": "infra",
    "rust-app": "infra",
}
CLASSES = ("deployable", "crate", "chart", "infra", "docs")
# 80%, as integer arithmetic: count / n >= 4 / 5.
THRESHOLD = (4, 5)
PROTO = "proto"
ACTIONS = "actions"
REPIN_PATH = ".github/workflows/repin.yaml"
WORKFLOWS = ".github/workflows"
RELEASE_APP_NAMES = ("RELEASE_APP_CLIENT_ID", "RELEASE_APP_PRIVATE_KEY")
# `secrets.NAME` and `secrets['NAME']` / `secrets["NAME"]`; expression contexts
# and secret names are case-insensitive in GitHub Actions.
_NAMES = "|".join(RELEASE_APP_NAMES)
RELEASE_REF = re.compile(r"\bsecrets\s*(?:\.\s*(" + _NAMES + r")\b|\[\s*['\"](" + _NAMES + r")['\"]\s*\])",
                         re.IGNORECASE)
GH_TIMEOUT = 60
MAX_PAGES = 10
SEMVER = re.compile(r"v([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})")


# --------------------------------------------------------------------------
# versions — vendored from yadgarhq/actions scripts/repin.py `semver`/`greatest`
# (numeric order, never lexical: "v0.2.9" < "v0.2.10"), fullmatched.
# --------------------------------------------------------------------------


def semver(tag):
    m = SEMVER.fullmatch(tag) if isinstance(tag, str) else None
    return tuple(int(g) for g in m.groups()) if m else None


def greatest(tags):
    """The greatest `vX.Y.Z` tag, or None when there is none."""
    released = [t for t in tags if semver(t)]
    return max(released, key=semver) if released else None


# --------------------------------------------------------------------------
# parsers — raw file text to facts
# --------------------------------------------------------------------------


def lock_sources(text, owner):
    """`[(producer, tag-or-None)]` for every in-org git package in a Cargo.lock."""
    out = set()
    prefix = f"git+https://github.com/{owner}/"
    for pkg in tomllib.loads(text).get("package", []):
        source = pkg.get("source", "")
        if not source.startswith(prefix):
            continue
        url = urllib.parse.urlsplit(source[len("git+"):].split("#", 1)[0])
        name = url.path.strip("/").split("/")[-1].removesuffix(".git")
        tag = urllib.parse.parse_qs(url.query).get("tag", [None])[0]
        out.add((name, tag))
    return sorted(out, key=lambda p: (p[0], p[1] or ""))


def pre_commit(text, owner):
    """`([actions revs], [hook ids])` of a .pre-commit-config.yaml.

    EVERY `yadgarhq/actions` block's rev, in file order: a second block is
    legal pre-commit, and keeping only one rev would let the other lag unseen.
    """
    doc = yaml.safe_load(text) or {}
    revs, ids = [], set()
    actions_url = f"https://github.com/{owner}/{ACTIONS}"
    for block in doc.get("repos", []):
        if block.get("repo") == actions_url:
            revs.append(str(block.get("rev")))
        ids.update(h["id"] for h in block.get("hooks", []))
    return revs, sorted(ids)


def repin_callers(text):
    """Every job's `uses:` in a workflow file, sorted."""
    doc = yaml.safe_load(text) or {}
    jobs = doc.get("jobs") or {}
    return sorted(str(j["uses"]) for j in jobs.values() if isinstance(j, dict) and "uses" in j)


def strings(node):
    """Every string VALUE in a parsed YAML document; keys and comments are not values."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def release_needs(text, owner):
    """The release App secret names one workflow file uses, sorted. Raises yaml.YAMLError."""
    doc = yaml.safe_load(text) or {}
    found = {(dot or index).upper() for s in strings(doc) for dot, index in RELEASE_REF.findall(s)}
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    for job in (jobs or {}).values():
        if (isinstance(job, dict) and job.get("secrets") == "inherit"
                and str(job.get("uses", "")).lower().startswith(f"{owner}/{ACTIONS}/".lower())):
            found.update(RELEASE_APP_NAMES)
    return sorted(found)


def proto_pin(text):
    return text.strip() if text is not None else None


# --------------------------------------------------------------------------
# enumeration and classes
# --------------------------------------------------------------------------


def in_sweep(repo, classes_cfg):
    """sweep.py's R1-R3, minus the class-topic test: that is P2's to report."""
    return (repo.get("visibility") == "public" and repo.get("archived") is False
            and repo.get("fork") is False and repo.get("disabled") is False
            and repo["name"] not in classes_cfg.get("sweep", {}).get("exclude", {}))


def class_of(topics):
    """`(class, None)` or `(None, why)`."""
    explicit = [t[len(EXPLICIT_PREFIX):] for t in topics if t.startswith(EXPLICIT_PREFIX)]
    if len(explicit) > 1:
        return None, f"{len(explicit)} `{EXPLICIT_PREFIX}*` topics, need at most one"
    if explicit:
        if explicit[0] not in CLASSES:
            return None, f"`{EXPLICIT_PREFIX}{explicit[0]}` is not a class ({', '.join(CLASSES)})"
        return explicit[0], None
    if DEPLOYABLE_TOPIC in topics:
        return "deployable", None
    found = [t[len(CLASS_PREFIX):] for t in topics if t.startswith(CLASS_PREFIX)]
    if len(found) != 1:
        return None, f"{len(found)} `{CLASS_PREFIX}*` topics, need exactly one"
    if found[0] not in CLASS_MAP:
        return None, f"`{CLASS_PREFIX}{found[0]}` maps to no class"
    return CLASS_MAP[found[0]], None


def finding(predicate, repo, what):
    return {"predicate": predicate, "repo": repo, "what": what}


# --------------------------------------------------------------------------
# P1 — pin parity
# --------------------------------------------------------------------------


def pins_of(repo):
    """Every `(producer, tag-or-None)` one repository pins."""
    pins = [tuple(p) for p in repo.get("lock_sources") or []]
    if repo.get("proto") is not None:
        pins.append((PROTO, repo["proto"]))
    pins += [(ACTIONS, rev) for rev in repo.get("actions_revs") or []]
    return list(dict.fromkeys(pins))


def pin_parity(snap):
    """`(findings, table, latest)`. `table` is producer -> tag -> [repos]."""
    findings, table = [], {}
    # A producer whose tag list could not be read is recorded as None.
    latest = {p: greatest(tags) for p, tags in snap["tags"].items() if tags is not None}
    for repo in sorted(snap["repos"], key=lambda r: r["name"]):
        if not in_sweep(repo, snap["classes"]):
            continue
        for producer, tag in pins_of(repo):
            table.setdefault(producer, {}).setdefault(tag or "(no tag)", []).append(repo["name"])
            want = latest.get(producer)
            if tag is None:
                findings.append(finding("P1", repo["name"], f"`{producer}` is a git source with no `tag=`"))
            elif snap["tags"].get(producer, []) is None:
                findings.append(finding("P1", repo["name"], f"`{producer}`'s tag list is unreadable (404)"))
            elif want is None:
                findings.append(finding("P1", repo["name"], f"`{producer}` has no released `vX.Y.Z` tag"))
            elif tag != want:
                findings.append(finding("P1", repo["name"], f"`{producer}` pinned at `{tag}`, latest `{want}`"))
        why = repin_gap(repo, snap["owner"])
        if why:
            findings.append(finding("P1", repo["name"], why))
    return findings, table, latest


def repin_gap(repo, owner):
    """Why a repository with an in-org git package lacks the repin caller, or None."""
    if not repo.get("lock_sources"):
        return None
    uses = repo.get("repin_uses")
    if uses is None:
        return f"pins in-org git crates but has no `{REPIN_PATH}`"
    caller = f"{owner}/{ACTIONS}/{REPIN_PATH}"
    if not any(u.startswith(caller + "@") for u in uses):
        return f"`{REPIN_PATH}` does not call `{caller}`"
    return None


# --------------------------------------------------------------------------
# P2 — hook-set conformance by class
# --------------------------------------------------------------------------


def required(members):
    """Hook ids carried by at least THRESHOLD of `members` (`{name: [ids]}`)."""
    n = len(members)
    counts = {}
    for ids in members.values():
        for i in set(ids):
            counts[i] = counts.get(i, 0) + 1
    num, den = THRESHOLD
    return {i: c for i, c in counts.items() if c * den >= n * num}


def hook_conformance(snap):
    """`(findings, classes)`. `classes` is class -> {members, required}."""
    findings, members = [], {c: {} for c in CLASSES}
    exempt = snap["classes"].get("exempt", {})
    for repo in sorted(snap["repos"], key=lambda r: r["name"]):
        if not in_sweep(repo, snap["classes"]) or repo["name"] in exempt:
            continue
        cls, why = class_of(repo.get("topics") or [])
        if cls is None:
            findings.append(finding("P2", repo["name"], f"no class: {why}"))
            continue
        if repo.get("hooks") is None:
            findings.append(finding("P2", repo["name"], "no `.pre-commit-config.yaml`"))
        members[cls][repo["name"]] = repo.get("hooks") or []
    out = {}
    for cls in CLASSES:
        req = required(members[cls])
        out[cls] = {"members": sorted(members[cls]), "required": req}
        for name, ids in sorted(members[cls].items()):
            missing = sorted(set(req) - set(ids))
            if missing:
                findings.append(finding("P2", name, f"{cls}: missing required {', '.join(f'`{m}`' for m in missing)}"))
    return findings, out


# --------------------------------------------------------------------------
# the report
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# P3 — release App secrets
# --------------------------------------------------------------------------


def p3_findings(doc):
    """P3 findings over the `secrets` job's document. Anything unread is a finding."""
    needs = doc.get("needs") if isinstance(doc, dict) else None
    vis = doc.get("visibility") if isinstance(doc, dict) else None
    if not isinstance(needs, dict) or not isinstance(vis, dict):
        result = doc.get("job_result") if isinstance(doc, dict) else None
        if result == "skipped":
            why = "the `secrets` job was skipped: it runs on `main` only, so P3 was not judged"
        else:
            why = (f"the release App secrets were not read: the `secrets` job answered nothing "
                   f"(job result: {result or 'unknown'}), so no repository's visibility is known")
        return [finding("P3", "(estate)", why)]
    unreadable = doc.get("unreadable") or {}
    if not isinstance(unreadable, dict) or not all(
            isinstance(w, list) and all(isinstance(x, str) for x in w) for w in unreadable.values()):
        return [finding("P3", "(estate)", "the `secrets` job's record of unparsable workflows is "
                        "malformed, so P3 cannot be judged")]
    out = []
    for name, whys in sorted(unreadable.items()):
        for why in whys:
            path, _, err = why.partition(": ")
            out.append(finding("P3", name, f"workflow `{path}` does not parse, so whether it uses "
                                           f"the release App secrets is unknown: {err}"))
    for name in sorted(needs):
        seen = vis.get(name)
        if not isinstance(seen, dict):
            out.append(finding("P3", name, "secret visibility was not read"))
        elif "error" in seen:
            out.append(finding("P3", name, f"secret visibility unreadable: {seen['error']}"))
        else:
            have = set(seen.get("org") or []) | set(seen.get("repo") or [])
            out += [finding("P3", name, f"`{s}` is used by its workflows but visible neither as an "
                                        "organisation secret nor as a repository secret")
                    for s in sorted(needs[name]) if s not in have]
    return out


def p3_section(doc):
    out = ["", "## P3 — release App secrets (who uses them sees them)", ""]
    if doc is None:
        return out + ["Not run: `check` was given no `--secrets` document."]
    needs = doc.get("needs") if isinstance(doc, dict) else None
    vis = doc.get("visibility") if isinstance(doc, dict) else None
    if not isinstance(needs, dict) or not isinstance(vis, dict):
        return out + ["Not read: see the findings."]
    out += ["| repository | uses | organisation secrets | repository secrets |", "| --- | --- | --- | --- |"]
    for name in sorted(needs):
        seen = vis.get(name) if isinstance(vis.get(name), dict) else {"error": "not read"}
        if "error" in seen:
            org = repo_level = "unreadable"
        else:
            org = ", ".join(s for s in seen.get("org") or [] if s in RELEASE_APP_NAMES) or "-"
            repo_level = ", ".join(s for s in seen.get("repo") or [] if s in RELEASE_APP_NAMES) or "-"
        out.append(f"| {name} | {', '.join(needs[name])} | {org} | {repo_level} |")
    return out


def report(snap, p3_doc=None):
    """`(markdown, exit code)`. `p3_doc` None: P3 not run (a local check)."""
    p1, table, latest = pin_parity(snap)
    p2, classes = hook_conformance(snap)
    p3 = [] if p3_doc is None else p3_findings(p3_doc)
    red = p1 or p2 or p3
    swept = sorted(r["name"] for r in snap["repos"] if in_sweep(r, snap["classes"]))
    out = ["# ADR-0561 audit", "",
           f"**{'RED' if red else 'GREEN'}**: {len(p1)} pin finding(s), {len(p2)} hook finding(s), "
           f"{len(p3)} secret finding(s). "
           f"Swept {len(swept)} public repositories: {', '.join(swept)}.", "",
           "## P1 — pin parity (latest released tag)", "",
           "| producer | latest | pinned tag | repositories |", "| --- | --- | --- | --- |"]
    for producer in sorted(table):
        for tag in sorted(table[producer], key=lambda t: semver(t) or (-1,)):
            mark = "" if tag == latest.get(producer) else " (behind)"
            out.append(f"| {producer} | {latest.get(producer) or '-'} | {tag}{mark} | {', '.join(table[producer][tag])} |")
    out += ["", "## P2 — hook-set conformance (required: carried by >= 80% of the class)", "",
            "| class | members | required hooks (count/n) |", "| --- | --- | --- |"]
    for cls in CLASSES:
        c = classes[cls]
        n = len(c["members"])
        req = ", ".join(f"{i} ({k}/{n})" for i, k in sorted(c["required"].items())) or "-"
        out.append(f"| {cls} | {', '.join(c['members']) or '(none public)'} | {req} |")
    out += ["", f"Class map: an `{EXPLICIT_PREFIX}<class>` topic names the class outright; "
            "without one, `yadgar-deployable` -> deployable, then "
            + ", ".join(f"`{k}` -> {v}" for k, v in CLASS_MAP.items()) + "."]
    out += p3_section(p3_doc) + ["", "## Findings", ""]
    out += [f"- {f['predicate']} `{f['repo']}`: {f['what']}" for f in p1 + p2 + p3] or ["- none"]
    return "\n".join(out) + "\n", 1 if red else 0


# --------------------------------------------------------------------------
# gathering — the only part that touches the network, through `gh api` GETs
# --------------------------------------------------------------------------


def gh_get(path, raw=False):
    """One GET. None on 404. Anything else that fails raises."""
    argv = ["gh", "api", "--method", "GET", path]
    if raw:
        argv[2:2] = ["-H", "Accept: application/vnd.github.raw+json"]
    done = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=GH_TIMEOUT)
    if done.returncode != 0:
        if "HTTP 404" in done.stderr:
            return None
        raise SystemExit(f"gh api {path}: {done.stderr.strip()[:300]}")
    return done.stdout if raw else json.loads(done.stdout)


def paged(get, path):
    """Every item of a listing, or None when its first page is a 404."""
    found = []
    for page in range(1, MAX_PAGES + 1):
        got = get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        if got is None and page == 1:
            return None
        if not isinstance(got, list):
            raise SystemExit(f"{path} page {page}: not a listing")
        found += got
        if len(got) < 100:
            return found
    raise SystemExit(f"{path} lists more than {MAX_PAGES * 100}; refused")


def gather(owner, get=gh_get):
    """The snapshot: every public repository's pins and hooks, and every producer's tags."""
    classes_text = get(f"repos/{owner}/{ACTIONS}/contents/classes.json", raw=True)
    if classes_text is None:
        raise SystemExit(f"{owner}/{ACTIONS} has no classes.json; refused")
    classes = json.loads(classes_text)
    snap = {"owner": owner, "classes": {"exempt": classes.get("exempt", {}),
                                        "sweep": {"exclude": classes.get("sweep", {}).get("exclude", {})}},
            "repos": [], "tags": {}}
    listing = paged(get, f"orgs/{owner}/repos?type=public")
    if listing is None:
        raise SystemExit(f"no repository listing for {owner}; refused")
    for meta in listing:
        repo = {k: meta.get(k) for k in ("name", "visibility", "archived", "fork", "disabled", "topics")}
        snap["repos"].append(repo)
        if not in_sweep(repo, snap["classes"]):
            continue
        base = f"repos/{owner}/{repo['name']}/contents"
        cfg = get(f"{base}/.pre-commit-config.yaml", raw=True)
        repo["actions_revs"], repo["hooks"] = pre_commit(cfg, owner) if cfg is not None else (None, None)
        repo["proto"] = proto_pin(get(f"{base}/PROTO_VERSION", raw=True))
        lock = get(f"{base}/Cargo.lock", raw=True)
        repo["lock_sources"] = lock_sources(lock, owner) if lock is not None else None
        if repo["lock_sources"]:
            caller = get(f"{base}/{REPIN_PATH}", raw=True)
            repo["repin_uses"] = repin_callers(caller) if caller is not None else None
    producers = {p for r in snap["repos"] for p, _ in pins_of(r)}
    for producer in sorted(producers):
        tags = paged(get, f"repos/{owner}/{producer}/tags")
        snap["tags"][producer] = None if tags is None else [t["name"] for t in tags]
    snap["repos"].sort(key=lambda r: r["name"])
    return snap


def swept_listing(owner, get):
    """The public repositories the sweep covers, as `gather` enumerates them."""
    classes_text = get(f"repos/{owner}/{ACTIONS}/contents/classes.json", raw=True)
    if classes_text is None:
        raise SystemExit(f"{owner}/{ACTIONS} has no classes.json; refused")
    cfg = {"sweep": {"exclude": json.loads(classes_text).get("sweep", {}).get("exclude", {})}}
    listing = paged(get, f"orgs/{owner}/repos?type=public")
    if listing is None:
        raise SystemExit(f"no repository listing for {owner}; refused")
    return sorted(m["name"] for m in listing if in_sweep(m, cfg))


def parse_error(exc):
    """A YAML error as its problem and position only.

    Never `str(exc)`: PyYAML quotes the offending source line, which can name a
    secret that is not a release secret, and this reason reaches public logs.
    """
    problem = getattr(exc, "problem", None)
    mark = getattr(exc, "problem_mark", None)
    where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
    return f"{problem or type(exc).__name__}{where}"


def needs(owner, get=gh_get):
    """`(found, unreadable)` over every swept repository.

    `found` is `{repo: [release App secret names]}` for each repository that
    uses one. `unreadable` is `{repo: ["<path>: why"]}` for each workflow file
    that does not parse: P3 reports it, and the other repositories are still read.
    """
    found, unreadable = {}, {}
    for name in swept_listing(owner, get):
        files = get(f"repos/{owner}/{name}/contents/{WORKFLOWS}")
        if files is None:
            continue
        if not isinstance(files, list):
            raise SystemExit(f"{owner}/{name} {WORKFLOWS}: not a directory listing")
        used = set()
        for f in files:
            if f.get("type") != "file" or not f["name"].endswith((".yaml", ".yml")):
                continue
            text = get(f"repos/{owner}/{name}/contents/{f['path']}", raw=True)
            if text is None:
                raise SystemExit(f"{owner}/{name} {f['path']}: listed but unreadable; refused")
            try:
                used.update(release_needs(text, owner))
            except yaml.YAMLError as exc:
                why = parse_error(exc)
                unreadable.setdefault(name, []).append(f"{f['path']}: {why}")
        if used:
            found[name] = sorted(used)
    return found, unreadable


def listed_names(get, path):
    """Every secret NAME of a `{total_count, secrets}` listing, sorted. Never a value."""
    names = []
    for page in range(1, MAX_PAGES + 1):
        got = get(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        if got is None:
            raise SystemExit(f"{path}: HTTP 404 (App not installed there, or no Secrets: read)")
        if not isinstance(got, dict) or not isinstance(got.get("secrets"), list):
            raise SystemExit(f"{path} page {page}: not a secret listing")
        names += [s["name"] for s in got["secrets"]]
        if len(got["secrets"]) < 100 or len(names) >= got.get("total_count", 0):
            return sorted(names)
    raise SystemExit(f"{path} lists more than {MAX_PAGES * 100}; refused")


def visibility(owner, names, get=gh_get):
    """`{repo: {"org": [...], "repo": [...]}}`, or `{"error": why}` for that one repository.

    Only RELEASE_APP_NAMES are kept. The result becomes a job output and a step
    `env:` value, and this repository's run logs are public: the rest of the
    organisation's secret names must not reach them.
    """
    out = {}
    for name in names:
        try:
            org = listed_names(get, f"repos/{owner}/{name}/actions/organization-secrets")
            own = listed_names(get, f"repos/{owner}/{name}/actions/secrets")
            out[name] = {"org": [n for n in org if n in RELEASE_APP_NAMES],
                         "repo": [n for n in own if n in RELEASE_APP_NAMES]}
        except (SystemExit, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            out[name] = {"error": str(exc)[:300]}
    return out


def load_p3_doc(path):
    """The `secrets` job's document; anything unreadable becomes `{}`, which P3 reports."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gather")
    g.add_argument("--owner", required=True)
    g.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--summary")
    c.add_argument("--outputs")
    c.add_argument("--secrets", dest="p3_doc")
    c.add_argument("--secrets-result", dest="p3_result")
    n = sub.add_parser("needs")
    n.add_argument("--owner", required=True)
    n.add_argument("--out", required=True)
    n.add_argument("--outputs", required=True)
    v = sub.add_parser("secrets")
    v.add_argument("--owner", required=True)
    v.add_argument("--needs", required=True)
    v.add_argument("--outputs", required=True)
    args = ap.parse_args(argv)
    if args.cmd == "needs":
        found, unreadable = needs(args.owner)
        if not found:
            raise SystemExit("no repository uses the release App secrets; an empty `repositories:` "
                             "would mint for every repository, refused")
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"needs": found, "unreadable": unreadable}, fh, sort_keys=True)
        write_outputs(args.outputs, {"repos": ",".join(sorted(found))})
        return 0
    if args.cmd == "secrets":
        with open(args.needs, encoding="utf-8") as fh:
            read = json.load(fh)
        found = read["needs"]
        doc = {"owner": args.owner, "needs": found, "unreadable": read.get("unreadable") or {},
               "visibility": visibility(args.owner, sorted(found))}
        write_outputs(args.outputs, {"visibility": json.dumps(doc, sort_keys=True)})
        return 0
    if args.cmd == "gather":
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(gather(args.owner), fh, indent=1, sort_keys=True)
            fh.write("\n")
        return 0
    with open(args.snapshot, encoding="utf-8") as fh:
        snap = json.load(fh)
    p3 = None if args.p3_doc is None else load_p3_doc(args.p3_doc)
    if p3 is not None and args.p3_result and "needs" not in p3:
        p3["job_result"] = args.p3_result
    text, code = report(snap, p3)
    sys.stdout.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    if args.outputs:
        write_outputs(args.outputs, {"verdict": "red" if code else "green", "report": text})
    return code


def write_outputs(path, values):
    """Append to a $GITHUB_OUTPUT file; a multi-line value gets a fresh delimiter."""
    with open(path, "a", encoding="utf-8") as fh:
        for key, value in values.items():
            value = value.rstrip("\n")
            if "\n" not in value:
                fh.write(f"{key}={value}\n")
                continue
            delim = f"EOF_{secrets.token_hex(16)}"
            fh.write(f"{key}<<{delim}\n{value}\n{delim}\n")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
