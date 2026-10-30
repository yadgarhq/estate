#!/usr/bin/env python3
"""Route the ADR-0561 audit's result to ONE GitHub issue (ruling, Max 2026-10-30).

A red scheduled run used to be visible only in the Actions tab, which nobody
reads on a schedule. This keeps exactly one open issue in step with the audit:

    verdict   no open issue            the open issue
    -------   ----------------------   ------------------------------------
    red       open it with the report  rewrite its body with this report
    green     nothing                  comment with the run, then close it
    crash     open it, saying so       comment with the run; keep the body

`crash` is any verdict other than `green` or `red`: the audit job failed before
`audit.py check` wrote one (a `gather` refusal, an API error, a timeout). It
never closes the issue, because the auditor not answering is not the estate
being clean.

THE ISSUE IS FOUND BY ITS EXACT TITLE among the open issues `github-actions[bot]`
opened, not by a label: a label must exist before an issue can carry it, and
creating one is a repository setting this workflow does not own. The oldest
match wins if several exist.

The workflow's `route` job runs this with `issues: write` and nothing else that
writes; the audit job itself stays `contents: read`. Inputs come from the
environment, never from `${{ }}` interpolated into a script: REPO, VERDICT,
REPORT, RUN_URL, and GH_TOKEN for `gh`.

Tests: python3 -m pytest scripts/tests -q
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

TITLE = "ADR-0561 audit: the estate is red"
BOT = "github-actions[bot]"
# GitHub refuses an issue body over 65536 characters.
MAX_BODY = 60_000
GH_TIMEOUT = 60


def body_for(verdict, report, run_url):
    if verdict == "red":
        head = (f"The nightly ADR-0561 audit is **RED** as of {run_url}. This body is rewritten "
                "by every red run and the issue closes on the first green one.\n\n")
        cut = MAX_BODY - len(head) - 200
        text = report.strip()
        if len(text) > cut:
            text = text[:cut] + f"\n\n(report cut at {cut} characters; the run's step summary has all of it)"
        return head + text + "\n"
    return (f"The ADR-0561 audit reached no verdict in {run_url}: the audit job failed before "
            "`audit.py check` ran, so the estate's state is unknown. Read the run's log.\n")


def ours(issues):
    """The open issues this workflow owns, oldest first."""
    found = [i for i in issues if i.get("title") == TITLE and "pull_request" not in i
             and (i.get("user") or {}).get("login") == BOT]
    return sorted(found, key=lambda i: i["number"])


def plan(verdict, report, run_url, issues):
    """The steps to take: `(kind, ...)` tuples, executed in order by `route`."""
    mine = ours(issues)
    if verdict not in ("green", "red"):
        verdict = "crash"
    body = body_for(verdict, report, run_url)
    if verdict == "green":
        if not mine:
            return []
        n = mine[0]["number"]
        return [("comment", n, {"body": f"Green in {run_url}. Closing."}),
                ("close", n, {"state": "closed", "state_reason": "completed"})]
    if not mine:
        return [("create", {"title": TITLE, "body": body})]
    if verdict == "red":
        return [("update", mine[0]["number"], {"body": body})]
    return [("comment", mine[0]["number"], {"body": body})]


def route(repo, verdict, report, run_url, call):
    base = f"repos/{repo}/issues"
    issues = call("GET", f"{base}?state=open&creator=github-actions%5Bbot%5D&per_page=100")
    for step in plan(verdict, report, run_url, issues):
        if step[0] == "create":
            call("POST", base, step[1])
        elif step[0] == "comment":
            call("POST", f"{base}/{step[1]}/comments", step[2])
        else:  # update, close
            call("PATCH", f"{base}/{step[1]}", step[2])


def gh_call(method, path, payload=None):
    """One `gh api` call; the payload goes on stdin as JSON. Any failure raises."""
    argv = ["gh", "api", "--method", method, path]
    if payload is not None:
        argv += ["--input", "-"]
    done = subprocess.run(argv, input=None if payload is None else json.dumps(payload),
                          capture_output=True, text=True, check=False, timeout=GH_TIMEOUT)
    if done.returncode != 0:
        raise SystemExit(f"gh api {method} {path}: {done.stderr.strip()[:300]}")
    return json.loads(done.stdout) if done.stdout.strip() else {}


def main():
    repo = os.environ.get("REPO", "")
    if "/" not in repo:
        raise SystemExit("REPO must be <owner>/<name>")
    route(repo, os.environ.get("VERDICT", ""), os.environ.get("REPORT", ""),
          os.environ.get("RUN_URL", ""), gh_call)
    return 0


if __name__ == "__main__":
    sys.exit(main())
