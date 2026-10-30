"""`scripts/audit_issue.py`: a red audit run is never silent (Max, 2026-10-30).

The decision is a pure function, `plan`, tested as a table:
{green, red, crash} x {no open issue, one open issue}. `route` executes a plan
through an injected transport, so no test touches the network.
"""

from __future__ import annotations

import pytest

import audit_issue as ai

RUN = "https://github.com/yadgarhq/estate/actions/runs/1"
REPORT = "# ADR-0561 audit\n\n**RED**: 1 pin finding(s), 0 hook finding(s).\n"
BOT = {"login": "github-actions[bot]"}


def issue(number, title=ai.TITLE, user=BOT, **extra):
    return {"number": number, "title": title, "user": user, **extra}


@pytest.mark.parametrize("verdict, report", [("red", REPORT), ("", ""), ("bogus", "")])
def test_red_or_crash_with_no_open_issue_opens_one(verdict, report):
    (step,) = ai.plan(verdict, report, RUN, [])
    assert step[0] == "create" and step[1]["title"] == ai.TITLE
    assert RUN in step[1]["body"]
    if verdict == "red":
        assert REPORT.strip() in step[1]["body"]
    else:
        assert "reached no verdict" in step[1]["body"]


def test_red_with_an_open_issue_rewrites_its_body():
    (step,) = ai.plan("red", REPORT, RUN, [issue(7)])
    assert step[0] == "update" and step[1] == 7
    assert REPORT.strip() in step[2]["body"] and RUN in step[2]["body"]


def test_a_crash_with_an_open_issue_comments_and_keeps_the_findings():
    (step,) = ai.plan("", "", RUN, [issue(7)])
    assert step[0] == "comment" and step[1] == 7
    assert "reached no verdict" in step[2]["body"] and RUN in step[2]["body"]


def test_green_closes_the_open_issue_with_a_comment():
    steps = ai.plan("green", "# ADR-0561 audit\n\n**GREEN**\n", RUN, [issue(7)])
    assert [s[0] for s in steps] == ["comment", "close"]
    assert all(s[1] == 7 for s in steps)
    assert RUN in steps[0][2]["body"]
    assert steps[1][2] == {"state": "closed", "state_reason": "completed"}


def test_green_with_no_open_issue_does_nothing():
    assert ai.plan("green", "x", RUN, []) == []


def test_only_the_bots_issue_with_the_exact_title_counts():
    others = [issue(1, title="ADR-0561 audit: something else"),
              issue(2, user={"login": "maxagahi"}),
              issue(3, pull_request={"url": "x"})]
    assert ai.plan("green", "x", RUN, others) == []
    (step,) = ai.plan("red", REPORT, RUN, others + [issue(9), issue(4)])
    assert step[:2] == ("update", 4)  # the oldest of several


def test_a_huge_report_is_cut_to_fit_an_issue_body():
    (step,) = ai.plan("red", "x" * 100_000, RUN, [])
    body = step[1]["body"]
    assert len(body) <= ai.MAX_BODY and RUN in body and "cut" in body


def test_route_lists_then_executes_the_plan_through_the_transport():
    calls = []

    def call(method, path, payload=None):
        calls.append((method, path, payload))
        return [issue(5)] if method == "GET" else {}

    ai.route("yadgarhq/estate", "green", "x", RUN, call)
    assert calls[0][:2] == ("GET", "repos/yadgarhq/estate/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100")
    assert [(m, p) for m, p, _ in calls[1:]] == [
        ("POST", "repos/yadgarhq/estate/issues/5/comments"),
        ("PATCH", "repos/yadgarhq/estate/issues/5"),
    ]


def test_route_creates_on_red_with_nothing_open():
    calls = []

    def call(method, path, payload=None):
        calls.append((method, path, payload))
        return [] if method == "GET" else {"number": 1}

    ai.route("yadgarhq/estate", "red", REPORT, RUN, call)
    assert [(m, p) for m, p, _ in calls] == [
        ("GET", "repos/yadgarhq/estate/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100"),
        ("POST", "repos/yadgarhq/estate/issues"),
    ]


def test_main_reads_its_inputs_from_the_environment(monkeypatch):
    seen = []
    monkeypatch.setattr(ai, "route", lambda *a: seen.append(a))
    env = {"REPO": "yadgarhq/estate", "VERDICT": "red", "REPORT": REPORT, "RUN_URL": RUN}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert ai.main() == 0
    assert seen[0][:4] == ("yadgarhq/estate", "red", REPORT, RUN)


def test_main_refuses_without_a_repository(monkeypatch):
    monkeypatch.delenv("REPO", raising=False)
    with pytest.raises(SystemExit, match="REPO"):
        ai.main()
