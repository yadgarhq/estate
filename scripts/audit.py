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
  P2  HOOK-SET CONFORMANCE BY CLASS (ruling, Max 2026-10-29). Classes are
      deployable, crate, chart, infra and docs. A hook id is REQUIRED in a class
      when at least 80% of that class's repositories carry it; a repository
      missing a required hook fails. Hook ids are counted across EVERY block of
      `.pre-commit-config.yaml` (pre-commit-hooks, actions, local), because the
      task names local hooks (`pytest-scripts`, `cargo-doc-*`) among the drift.

The class of a repository is derived from GitHub topics, in this order: the
`yadgar-deployable` topic makes it `deployable`; otherwise its ONE
`yadgar-class-<name>` topic is mapped through CLASS_MAP. Zero or several class
topics is a finding (the topics are mutable by any repository admin).

ENUMERATION matches `yadgarhq/actions` `scripts/sweep.py`: public repositories
only (the workflow's GITHUB_TOKEN cannot read a private one, and a local run
with a wider token must see the same estate), not archived, not a fork, not
disabled, not named in `classes.json` `sweep.exclude`. `classes.json` `exempt`
(the producer `actions`) is exempt from P2 only. The auditor includes ITSELF:
this repository is a consumer like any other (ADR-0561).

Commands:

    audit.py gather --owner O --out snapshot.json      read GitHub, write facts
    audit.py check  --snapshot snapshot.json [--summary PATH]

`check` writes a Markdown report and exits 1 when any predicate fails. Both
read only: `gather` issues GET requests through `gh api` and nothing else.

Tests: python3 -m pytest scripts/tests -q
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
import urllib.parse

import yaml

DEPLOYABLE_TOPIC = "yadgar-deployable"
CLASS_PREFIX = "yadgar-class-"
# `yadgar-class-*` topic -> ruling class. `yadgar-deployable` is checked first,
# so `service` and `seeder`'s `rust-helm` both land in `deployable`. THREE FITS
# ARE LOOSE and the report says so rather than hiding it: `base` holds argocd
# and proto (and the private docs), `rust-app` holds estate and yadgar, and no
# topic marks a docs repository, so `docs` has no public member.
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
    return findings, table, latest


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


def report(snap):
    """`(markdown, exit code)`."""
    p1, table, latest = pin_parity(snap)
    p2, classes = hook_conformance(snap)
    swept = sorted(r["name"] for r in snap["repos"] if in_sweep(r, snap["classes"]))
    out = ["# ADR-0561 audit", "",
           f"**{'RED' if p1 or p2 else 'GREEN'}**: {len(p1)} pin finding(s), {len(p2)} hook finding(s). "
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
    out += ["", "Class map: `yadgar-deployable` -> deployable, then "
            + ", ".join(f"`{k}` -> {v}" for k, v in CLASS_MAP.items())
            + ". No topic marks a docs repository.", "", "## Findings", ""]
    out += [f"- {f['predicate']} `{f['repo']}`: {f['what']}" for f in p1 + p2] or ["- none"]
    return "\n".join(out) + "\n", 1 if p1 or p2 else 0


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
    producers = {p for r in snap["repos"] for p, _ in pins_of(r)}
    for producer in sorted(producers):
        tags = paged(get, f"repos/{owner}/{producer}/tags")
        snap["tags"][producer] = None if tags is None else [t["name"] for t in tags]
    snap["repos"].sort(key=lambda r: r["name"])
    return snap


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gather")
    g.add_argument("--owner", required=True)
    g.add_argument("--out", required=True)
    c = sub.add_parser("check")
    c.add_argument("--snapshot", required=True)
    c.add_argument("--summary")
    args = ap.parse_args(argv)
    if args.cmd == "gather":
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(gather(args.owner), fh, indent=1, sort_keys=True)
            fh.write("\n")
        return 0
    with open(args.snapshot, encoding="utf-8") as fh:
        text, code = report(json.load(fh))
    sys.stdout.write(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
