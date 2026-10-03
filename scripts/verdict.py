#!/usr/bin/env python3
"""Decide whether estate smoke may run the rows, from argocd-verify's verdict.

LEDGER 675, STAGE 5 of `plans/settled-state-smoke-gate.md` (yadgarhq/docs).
`smoke.yaml`'s `verdict` job runs this on `ubuntu-latest`. It answers one
question: is there a GREEN settled-state verdict for the epoch argocd `main`
renders now, which no smoke run has certified yet? Only then is `run=true`.

THE EPOCH `E = (K, A)`. `K` is the render key: sha256 of the reviewed table
`T` (`scripts/gates/yadgar_render.sha256`) followed by the canonical JSON of
`spec.source` of `applications/yadgar.yaml`. `A` is the anchor: the oldest
commit, walking newest-first through the commits that touched either file,
whose `K` still equals the current `K`. The argocd gate (`settled_gate.py`)
computes the same `E` from a checkout. The two MUST agree byte for byte, so
the encoding below is pinned and `scripts/tests/test_verdict_key.py` holds
frozen vectors that argocd's tests assert too (ruling 4, ADR-0844).

THREE OUTCOMES, kept apart on purpose:
  * `Red` — the job FAILS and `run=false`: a token argocd-verify rejects
    (401/403/404, never "waiting", or smoke goes silent when the token
    expires), an empty token, a consistency mismatch on argocd `main`, a
    verdict whose `A` matches but whose `K` does not, a malformed verdict, or
    estate's own token unable to list its `smoke-certified-` artifacts.
  * a quiet `run=false` — no verdict for `E` yet, a red verdict, or `E`
    already certified. The job succeeds; the summary says which.
  * `run=true` — a green verdict for `E` and no certificate for `E`.

Tokens never reach stdout, an exception message, or a redirect target.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

import yaml

API = "https://api.github.com"
ARGOCD = "yadgarhq/argocd"
VERIFY = "yadgarhq/argocd-verify"
TABLE_PATH = "scripts/gates/yadgar_render.sha256"
APP_PATH = "applications/yadgar.yaml"
PIN_PATH = "scripts/chart_pin.json"
ALLOWED_REPO_URL = "ghcr.io/yadgarhq/charts"
ALLOWED_CHART = "yadgar"
FORBIDDEN_SOURCE_KEYS = ("path", "kustomize", "plugin")
VERDICT_ARTIFACT = "settled-verdict"
# argocd-verify's default branch. ADR-0844: the gate runs main's copy only.
VERIFY_BRANCH = "main"
# `settled.yaml` judges on its cron or on a hand re-judge; nothing else writes a verdict.
VERDICT_EVENTS = ("schedule", "workflow_dispatch")
VERDICT_WORKFLOW = ".github/workflows/settled.yaml"
VERDICT_FILE = "verdict.json"
SMOKE_WORKFLOW = ".github/workflows/smoke.yaml"
CERT_PREFIX = "smoke-certified-"
# A walk that needs more file reads than this refuses rather than guesses: the
# argocd gate walks a checkout without limit, so a truncated walk here could
# name a different anchor. Fail closed; a person reads why.
MAX_FILE_READS = 8
# Verdicts are uploaded once per epoch (plus re-judges), so the current
# epoch's verdict is among the newest few or it does not exist yet.
MAX_VERDICT_CANDIDATES = 5
# The gate's budget: a verdict is due by A's committer date + 3900 s
# (`settled_gate.BUDGET_SECONDS`). Past that plus a margin of three gate polls,
# "no verdict" stops meaning "waiting" and means the gate and estate disagree.
GATE_BUDGET = timedelta(seconds=3900)
DEADLINE_MARGIN = timedelta(minutes=30)
# The commits API's page size. A full page means history may continue on the
# next page, and the walk would then call "the oldest listed" an anchor it is not.
PAGE = 100
TOKEN_PROBES = ("real", "own-github-token", "bogus")
BOGUS_TOKEN = "bogus-token-for-the-401-arm"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Red(Exception):
    """A refusal: the job fails, and the rows do not run."""


@dataclass
class Response:
    status: int
    body: bytes
    location: str | None = None


# (url, token or None) -> Response. Injected so the decision table is tested
# against fixtures rather than against GitHub.
Transport = Callable[[str, "str | None"], Response]


@dataclass
class Decision:
    run: bool
    epoch: str
    summary: str
    verdict_url: str = ""


# ── the render key ──────────────────────────────────────────────────────────


def _refuse_unencodable(node, where: str) -> None:
    """Refuse what YAML 1.1 can produce and canonical JSON cannot carry.

    PyYAML reads `on:`/`yes:` keys as booleans and `1:` as an int; mixed key
    types make `sort_keys` raise, and a lone bool key would encode as "true".
    An unquoted date is a `datetime.date`, which json cannot serialise. Each
    is a red naming the field, never a traceback and never a silent coercion.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if not isinstance(key, str):
                raise Red(
                    f"spec.source{where} has a key {key!r} that YAML read as "
                    f"{type(key).__name__}, not a string; quote it in argocd"
                )
            _refuse_unencodable(value, f"{where}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _refuse_unencodable(value, f"{where}[{i}]")
    elif not (node is None or isinstance(node, (str, int, float, bool))):
        raise Red(
            f"spec.source{where} is a {type(node).__name__} ({node!r}), which "
            "canonical JSON cannot carry; quote it in argocd"
        )


def canonical(source) -> bytes:
    """The pinned encoding argocd's gate uses. Change both or neither."""
    _refuse_unencodable(source, "")
    return json.dumps(
        source, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def spec_source(app_bytes: bytes) -> dict:
    try:
        doc = yaml.safe_load(app_bytes)
    except yaml.YAMLError as err:
        raise Red(f"{APP_PATH} does not parse: {err}") from None
    source = (doc or {}).get("spec", {}).get("source") if isinstance(doc, dict) else None
    if not isinstance(source, dict):
        raise Red(f"{APP_PATH} has no mapping at spec.source")
    return source


def render_key(table_bytes: bytes, app_bytes: bytes) -> str:
    return hashlib.sha256(table_bytes + canonical(spec_source(app_bytes))).hexdigest()


# ── the public checks the gate also runs on every poll ─────────────────────


def check_consistency(app_bytes: bytes, table_bytes: bytes, pin_bytes: bytes) -> str:
    """Step 0 (allow-list) and step 1 (one pin in three places). Returns P."""
    source = spec_source(app_bytes)
    if source.get("repoURL") != ALLOWED_REPO_URL or source.get("chart") != ALLOWED_CHART:
        raise Red(
            f"spec.source is repoURL {source.get('repoURL')!r} chart "
            f"{source.get('chart')!r}; only {ALLOWED_REPO_URL!r} / {ALLOWED_CHART!r} is allowed"
        )
    extra = [k for k in FORBIDDEN_SOURCE_KEYS if k in source]
    if extra:
        raise Red(f"spec.source carries {extra}, which the allow-list refuses")
    pin = source.get("targetRevision")
    if not isinstance(pin, str) or not pin:
        raise Red(f"spec.source.targetRevision is {pin!r}, not a version string")
    lines = [
        ln for ln in table_bytes.decode("utf-8", "replace").splitlines()
        if ln.strip() and not ln.startswith("#")
    ]
    if not lines or lines[0].split() != ["targetRevision", pin]:
        found = lines[0] if lines else "nothing"
        raise Red(f"{TABLE_PATH}'s first data line is {found!r}, not 'targetRevision  {pin}'")
    try:
        tag = json.loads(pin_bytes).get("chart_tag")
    except (ValueError, AttributeError):
        raise Red(f"{PIN_PATH} does not parse as a JSON object") from None
    if tag != f"v{pin}":
        raise Red(f"{PIN_PATH} chart_tag is {tag!r}, but the pin is {pin!r} (want 'v{pin}')")
    return pin


# ── GitHub ──────────────────────────────────────────────────────────────────


class GitHub:
    """One token, one transport. Every non-2xx is a red naming the status."""

    def __init__(self, transport: Transport, token: str | None, who: str):
        self.transport = transport
        self.token = token
        self.who = who

    def _get(self, path: str) -> Response:
        url = path if path.startswith("https://") else API + path
        resp = self.transport(url, self.token)
        if resp.status in (401, 403, 404):
            raise Red(
                f"{self.who} answered {resp.status} to GET {url}: the token is "
                "expired, rejected, or has no access. This is a refusal, not 'waiting'."
            )
        if resp.status in (301, 302, 303, 307, 308) and resp.location:
            return resp
        if not 200 <= resp.status < 300:
            raise Red(f"{self.who} answered {resp.status} to GET {url}")
        return resp

    def json(self, path: str):
        try:
            return json.loads(self._get(path).body)
        except ValueError:
            raise Red(f"{self.who} answered non-JSON to GET {path}") from None

    def raw(self, path: str) -> bytes:
        return self._get(path).body

    def download(self, path: str) -> bytes:
        """Follow the artifact redirect WITHOUT the token (it must stay on the API host)."""
        resp = self._get(path)
        if resp.location:
            hop = self.transport(resp.location, None)
            if not 200 <= hop.status < 300:
                raise Red(f"the artifact store answered {hop.status} for {path}")
            return hop.body
        return resp.body


def contents(gh: GitHub, path: str, ref: str) -> bytes:
    return gh.raw(f"/repos/{ARGOCD}/contents/{path}?ref={ref}")


# ── the anchor ──────────────────────────────────────────────────────────────


def _commit_list(gh: GitHub, path: str, head: str) -> list[dict]:
    q = urllib.parse.urlencode({"sha": head, "path": path, "per_page": PAGE})
    items = gh.json(f"/repos/{ARGOCD}/commits?{q}")
    if len(items) >= PAGE:
        raise Red(f"argocd lists {len(items)} commits touching {path}, a full page; refusing to guess A from a truncated history")
    out = []
    for item in items:
        sha = item["sha"]
        if len(item.get("parents", [])) > 1:
            raise Red(f"commit {sha} touching {path} has two parents; argocd main is squash-only")
        date = datetime.fromisoformat(item["commit"]["committer"]["date"].replace("Z", "+00:00"))
        out.append({"sha": sha, "date": date})
    return out


def merge_history(lists: dict[str, list[dict]]) -> list[str]:
    """Merge path-filtered lists into one newest-first order, or refuse.

    The commits API filters on one path, so two lists are merged by committer
    date. That is only an order when it is unambiguous: two distinct commits
    at one instant, or a merged order contradicting either list's own API
    order, is a red rather than a guess.
    """
    dates: dict[str, datetime] = {}
    for items in lists.values():
        for it in items:
            dates[it["sha"]] = it["date"]
    merged = sorted(dates, key=lambda s: dates[s], reverse=True)
    for i in range(1, len(merged)):
        if dates[merged[i]] == dates[merged[i - 1]]:
            raise Red(f"commits {merged[i - 1]} and {merged[i]} share a committer date; order is ambiguous")
    pos = {s: i for i, s in enumerate(merged)}
    for path, items in lists.items():
        idx = [pos[it["sha"]] for it in items]
        if idx != sorted(idx):
            raise Red(f"the commit order for {path} contradicts committer dates; order is ambiguous")
    return merged


def find_anchor(gh: GitHub, head: str, now: dict[str, bytes], key_now: str) -> tuple[str, datetime]:
    """A and its committer date: walking newest-first, the last commit whose K still equals `key_now`."""
    lists = {p: _commit_list(gh, p, head) for p in (TABLE_PATH, APP_PATH)}
    merged = merge_history(lists)
    if not merged:
        raise Red(f"argocd lists no commit touching {TABLE_PATH} or {APP_PATH} at {head}")
    pos = {s: i for i, s in enumerate(merged)}
    dates = {it["sha"]: it["date"] for items in lists.values() for it in items}
    cache: dict[tuple[str, str], bytes] = {}
    for p, items in lists.items():
        if items:  # the newest version of each file is the file at `head`
            cache[(p, items[0]["sha"])] = now[p]
    reads = 0

    def version_at(path: str, commit: str) -> bytes | None:
        nonlocal reads
        older = [it["sha"] for it in lists[path] if pos[it["sha"]] >= pos[commit]]
        if not older:
            return None  # the file did not exist yet
        v = older[0]
        if (path, v) not in cache:
            reads += 1
            if reads > MAX_FILE_READS:
                raise Red(f"the anchor walk needs more than {MAX_FILE_READS} file reads; refusing to guess A")
            cache[(path, v)] = contents(gh, path, v)
        return cache[(path, v)]

    anchor = merged[0]
    for commit in merged[1:]:
        table, app = version_at(TABLE_PATH, commit), version_at(APP_PATH, commit)
        if table is None or app is None:
            break
        try:
            key = render_key(table, app)
        except Red:
            break  # an older version that does not encode is not this epoch
        if key != key_now:
            break
        anchor = commit
    return anchor, dates[anchor]


# ── artifacts ───────────────────────────────────────────────────────────────


def _artifacts(gh: GitHub, repo: str, name: str, repo_id: int | None, branch: str) -> list[dict]:
    """Unexpired artifacts called exactly `name`, uploaded by `repo` itself on `branch`.

    `head_branch` alone is spoofable (a fork can name a branch `main`), so the
    run's head repository must be the repository itself. `repo_id` None means
    "the repository the listing answered for", read from each artifact.
    """
    q = urllib.parse.urlencode({"name": name, "per_page": 100})
    keep = []
    for art in gh.json(f"/repos/{repo}/actions/artifacts?{q}").get("artifacts", []):
        run = art.get("workflow_run") or {}
        if (
            art.get("name") == name
            and not art.get("expired")
            and run.get("head_branch") == branch
            and run.get("repository_id") is not None
            and run.get("head_repository_id") == run.get("repository_id")
            and (repo_id is None or run.get("repository_id") == repo_id)
        ):
            keep.append(art)
    return sorted(keep, key=lambda a: a.get("id", 0), reverse=True)


def _run_is(gh: GitHub, repo: str, run_id: int, workflow: str, repo_id: int, branch: str,
            events: tuple[str, ...] | None = None) -> bool:
    """The run record, re-checked: the listing's fields are repeated on purpose, so a
    disagreement between the two layers drops the artifact rather than trusting either."""
    run = gh.json(f"/repos/{repo}/actions/runs/{run_id}")
    return (
        (events is None or run.get("event") in events)
        and run.get("path") == workflow
        and run.get("head_branch") == branch
        and (run.get("head_repository") or {}).get("id") == repo_id
    )


def read_verdict(blob: bytes, where: str) -> dict:
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            v = json.loads(zf.read(VERDICT_FILE))
    except (zipfile.BadZipFile, KeyError, ValueError):
        raise Red(f"the verdict at {where} has no readable {VERDICT_FILE}") from None
    if (
        isinstance(v, dict) and "K" in v and "A" in v and v["K"] is None and v["A"] is None
        and v.get("result") == "red" and isinstance(v.get("clause"), str)
        and isinstance(v.get("S"), str) and HEX40.match(v["S"])
    ):
        return v  # the gate refused the key: a red with no epoch, named by find_verdict
    ok = (
        isinstance(v, dict)
        and isinstance(v.get("K"), str) and HEX64.match(v["K"])
        and isinstance(v.get("A"), str) and HEX40.match(v["A"])
        and isinstance(v.get("S"), str) and HEX40.match(v["S"])
        and isinstance(v.get("P"), str)
        and v.get("result") in ("green", "red")
        and (v["result"] == "green" or isinstance(v.get("clause"), str))
    )
    if not ok:
        raise Red(f"the verdict at {where} is malformed: want S, P, K, A, result (and clause when red)")
    return v


def find_verdict(gh: GitHub, key: str, anchor: str) -> tuple[dict, str] | None:
    candidates = _artifacts(gh, VERIFY, VERDICT_ARTIFACT, None, VERIFY_BRANCH)
    for art in candidates[:MAX_VERDICT_CANDIDATES]:
        run_id, repo_id = art["workflow_run"]["id"], art["workflow_run"]["repository_id"]
        if not _run_is(gh, VERIFY, run_id, VERDICT_WORKFLOW, repo_id, VERIFY_BRANCH, VERDICT_EVENTS):
            continue
        url = f"https://github.com/{VERIFY}/actions/runs/{run_id}"
        v = read_verdict(gh.download(f"/repos/{VERIFY}/actions/artifacts/{art['id']}/zip"), url)
        if v["K"] is None:
            # Newer than any verdict for this epoch: the gate's latest word is a refusal.
            raise Red(f"the gate refused the key at S {v['S']}: {v['clause']} ({url})")
        if v["A"] == anchor and v["K"] != key:
            raise Red(
                f"key computation disagrees: the verdict at {url} names anchor {anchor} "
                f"with K {v['K']}, estate computes K {key}"
            )
        if v["A"] == anchor and v["K"] == key:
            return v, url
    return None


def certified(gh: GitHub, repo: str, repo_id: int, branch: str, epoch: str) -> bool:
    for art in _artifacts(gh, repo, CERT_PREFIX + epoch, repo_id, branch):
        if _run_is(gh, repo, art["workflow_run"]["id"], SMOKE_WORKFLOW, repo_id, branch):
            return True
    return False


# ── the decision ────────────────────────────────────────────────────────────


@dataclass
class Inputs:
    estate_repo: str
    estate_repo_id: int
    estate_branch: str
    recertify: bool = False
    now: datetime | None = None


def decide(public: GitHub, verify: GitHub, estate: GitHub, inp: Inputs) -> Decision:
    head = public.json(f"/repos/{ARGOCD}/branches/main")["commit"]["sha"]
    now = {p: contents(public, p, head) for p in (TABLE_PATH, APP_PATH, PIN_PATH)}
    pin = check_consistency(now[APP_PATH], now[TABLE_PATH], now[PIN_PATH])
    key = render_key(now[TABLE_PATH], now[APP_PATH])
    anchor, anchored_at = find_anchor(public, head, now, key)
    epoch = f"{key}-{anchor}"
    where = f"render `{key}` at `{anchor}` (pin {pin}, argocd main `{head}`)"
    if not verify.token:
        raise Red(
            "the argocd-verify read token is empty: the `verdict-reader` environment "
            "or its ARGOCD_VERIFY_READ_TOKEN secret is missing (MIGRATION_NOTES item 8)"
        )
    found = find_verdict(verify, key, anchor)
    if found is None:
        due = anchored_at + GATE_BUDGET + DEADLINE_MARGIN
        if (inp.now or datetime.now(timezone.utc)) > due:
            raise Red(
                f"no verdict for epoch {epoch} past the gate's deadline ({due.isoformat()}); "
                "the gate and estate may disagree on A"
            )
        return Decision(False, epoch, f"waiting for a verdict on {where}")
    v, url = found
    if v["result"] == "red":
        return Decision(False, epoch, f"the verdict on {where} is RED: {v['clause']}", url)
    if not inp.recertify and certified(estate, inp.estate_repo, inp.estate_repo_id, inp.estate_branch, epoch):
        return Decision(False, epoch, f"already certified: {where}", url)
    return Decision(True, epoch, f"green verdict on {where}; running the rows", url)


# ── the job ─────────────────────────────────────────────────────────────────


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_request(url: str, token: str | None) -> urllib.request.Request:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    if url.startswith(API + "/") and "/contents/" in url:
        req.add_header("Accept", "application/vnd.github.raw")
    if token and url.startswith(API + "/"):
        # Unredirected: the artifact redirect leaves api.github.com, the token must not.
        req.add_unredirected_header("Authorization", f"Bearer {token}")
        req.add_unredirected_header("X-GitHub-Api-Version", "2022-11-28")
    return req


def http_transport(url: str, token: str | None) -> Response:
    req = build_request(url, token)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as r:
            return Response(r.status, r.read())
    except urllib.error.HTTPError as err:
        return Response(err.code, err.read() or b"", err.headers.get("Location"))


def choose_token(probe: str, env: dict) -> str:
    probe = probe or "real"
    if probe not in TOKEN_PROBES:
        raise Red(f"token_probe is {probe!r}; want one of {TOKEN_PROBES}")
    if probe == "own-github-token":
        return env.get("GITHUB_TOKEN", "")
    if probe == "bogus":
        return BOGUS_TOKEN
    return env.get("VERDICT_TOKEN", "")


def _emit(env: dict, run: bool, epoch: str, url: str, summary: str) -> None:
    if env.get("GITHUB_OUTPUT"):
        with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write(f"run={'true' if run else 'false'}\nepoch={epoch}\nverdict_url={url}\n")
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(f"### settled-state verdict\n\n{summary}\n")


def main(env: dict | None = None, transport: Transport = http_transport) -> int:
    env = dict(os.environ) if env is None else env
    try:
        own = env.get("GITHUB_TOKEN", "")
        inp = Inputs(
            estate_repo=env["GITHUB_REPOSITORY"],
            estate_repo_id=int(env["GITHUB_REPOSITORY_ID"]),
            estate_branch=env.get("ESTATE_DEFAULT_BRANCH") or "main",
            recertify=env.get("RECERTIFY", "") == "true",
        )
        verify = GitHub(transport, choose_token(env.get("TOKEN_PROBE", ""), env), "argocd-verify")
        d = decide(
            GitHub(transport, own, "argocd (public)"),
            verify,
            GitHub(transport, own, "estate's own artifact listing (needs actions: read)"),
            inp,
        )
    except (Red, KeyError, ValueError, TypeError) as err:
        msg = str(err) if isinstance(err, Red) else f"an input or an API answer has an unexpected shape: {err!r}"
        print(f"::error title=verdict refused::{msg}")
        _emit(env, False, "", "", f"**REFUSED** — {msg}")
        return 1
    print(d.summary)
    _emit(env, d.run, d.epoch, d.verdict_url, d.summary + (f"\n\nVerdict run: {d.verdict_url}" if d.verdict_url else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
