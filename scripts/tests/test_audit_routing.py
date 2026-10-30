"""Max's ruling of 2026-10-30 on `scripts/audit.py`: three additions.

1. EXPLICIT CLASS TOPICS. An `estate-class-<class>` topic names a repository's
   ruling class outright and wins over `yadgar-deployable` and the legacy
   `yadgar-class-*` map, which stays the fallback. The prefix is NOT
   `yadgar-class-`: `yadgarhq/actions` `sweep.py` refuses a repository with two
   topics under that prefix.
2. THE REPIN CALLER. A repository that pins an in-org git crate must carry
   `.github/workflows/repin.yaml` calling the shared repin workflow, or nothing
   ever advances the pin P1 reports as behind.
3. RED-RUN ROUTING. `check --outputs` hands the verdict and the report to the
   workflow's `route` job; `scripts/audit_issue.py` (its own tests) turns them
   into one GitHub issue.

Every rule has a red case and a pristine companion (ADR-0646).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

import audit
from test_audit import FIX, ROOT, SECRETS_CTX, by_name, pristine, repo, whats

CALLER = "yadgarhq/actions/.github/workflows/repin.yaml@main"


# --------------------------------------------------------------------------
# 1. explicit class topics
# --------------------------------------------------------------------------


@pytest.mark.parametrize("topics, want", [
    (["estate-class-docs"], "docs"),
    (["estate-class-infra", "yadgar-class-rust-app"], "infra"),
    (["estate-class-crate", "yadgar-class-base"], "crate"),
    # The explicit topic wins over `yadgar-deployable` too.
    (["estate-class-chart", "yadgar-class-service", "yadgar-deployable"], "chart"),
    # No explicit topic: the legacy order is unchanged.
    (["yadgar-class-service", "yadgar-deployable"], "deployable"),
    (["yadgar-class-base"], "infra"),
])
def test_an_explicit_class_topic_wins_and_the_legacy_map_is_the_fallback(topics, want):
    assert audit.class_of(topics) == (want, None)


@pytest.mark.parametrize("topics, why", [
    (["estate-class-docs", "estate-class-infra"], "2 `estate-class-*` topics"),
    (["estate-class-service"], "`estate-class-service` is not a class"),
    (["estate-class-nope", "yadgar-class-base"], "`estate-class-nope` is not a class"),
])
def test_several_or_unknown_explicit_class_topics_are_a_finding(topics, why):
    cls, got = audit.class_of(topics)
    assert cls is None and why in got


def test_the_explicit_prefix_cannot_collide_with_the_sweeps_prefix():
    assert not audit.EXPLICIT_PREFIX.startswith(audit.CLASS_PREFIX)
    assert not audit.CLASS_PREFIX.startswith(audit.EXPLICIT_PREFIX)


def test_p2_places_a_repository_by_its_explicit_topic():
    snap = pristine()
    by_name(snap, "estate")["topics"] = ["estate-class-docs", "yadgar-class-rust-app"]
    findings, classes = audit.hook_conformance(snap)
    assert findings == []
    assert classes["docs"]["members"] == ["estate"]
    assert classes["infra"]["members"] == []


def test_the_report_names_both_topic_families():
    text, _ = audit.report(pristine())
    assert "`estate-class-<class>`" in text
    assert "No topic marks a docs repository" not in text


# --------------------------------------------------------------------------
# 2. the repin caller
# --------------------------------------------------------------------------


def test_repin_callers_reads_every_jobs_uses():
    text = ("on: {schedule: [{cron: '1 2 * * *'}]}\njobs:\n  repin:\n"
            f"    uses: {CALLER}\n  other:\n    runs-on: ubuntu-latest\n    steps: []\n")
    assert audit.repin_callers(text) == [CALLER]
    assert audit.repin_callers("jobs: {}\n") == []
    assert audit.repin_callers("") == []


def test_p1_pristine_consumers_carry_the_repin_caller():
    assert audit.pin_parity(pristine())[0] == []


def test_p1_a_consumer_without_a_repin_caller_fails():
    snap = pristine()
    by_name(snap, "seeder")["repin_uses"] = None
    assert whats(audit.pin_parity(snap)[0]) == [
        ("seeder", "pins in-org git crates but has no `.github/workflows/repin.yaml`")]


def test_p1_a_repin_file_that_does_not_call_the_shared_workflow_fails():
    snap = pristine()
    by_name(snap, "iam")["repin_uses"] = ["someone/else/.github/workflows/repin.yaml@main"]
    by_name(snap, "gateway")["repin_uses"] = []
    assert whats(audit.pin_parity(snap)[0]) == [
        ("gateway", "`.github/workflows/repin.yaml` does not call "
                    "`yadgarhq/actions/.github/workflows/repin.yaml`"),
        ("iam", "`.github/workflows/repin.yaml` does not call "
                "`yadgarhq/actions/.github/workflows/repin.yaml`"),
    ]


def test_p1_a_repository_with_no_in_org_git_crate_needs_no_repin_caller():
    snap = pristine()
    for name in ("dial", "store", "estate"):  # [] or None lock_sources
        assert not by_name(snap, name).get("repin_uses")
    assert audit.pin_parity(snap)[0] == []


def test_gather_reads_the_repin_caller_only_for_an_in_org_consumer():
    lock = ('version = 4\n[[package]]\nname = "yadgar-dial"\nversion = "0.1.0"\n'
            'source = "git+https://github.com/o/dial?tag=v0.1.0#abc"\n')
    world = {
        "repos/o/actions/contents/classes.json": json.dumps({"exempt": {}, "sweep": {"exclude": {}}}),
        "orgs/o/repos?type=public&per_page=100&page=1": [
            {"name": n, "visibility": "public", "archived": False, "fork": False, "disabled": False,
             "topics": ["yadgar-class-base"]} for n in ("a", "b")],
        "repos/o/a/contents/.pre-commit-config.yaml": None,
        "repos/o/a/contents/PROTO_VERSION": None,
        "repos/o/a/contents/Cargo.lock": lock,
        "repos/o/a/contents/.github/workflows/repin.yaml": f"jobs:\n  r:\n    uses: {CALLER.replace('yadgarhq', 'o')}\n",
        "repos/o/b/contents/.pre-commit-config.yaml": None,
        "repos/o/b/contents/PROTO_VERSION": None,
        "repos/o/b/contents/Cargo.lock": None,
        "repos/o/dial/tags?per_page=100&page=1": [{"name": "v0.1.0"}],
    }
    calls = []

    def get(path, raw=False):
        calls.append(path)
        return world[path]

    snap = audit.gather("o", get)
    assert by_name(snap, "a")["repin_uses"] == ["o/actions/.github/workflows/repin.yaml@main"]
    assert "repin_uses" not in by_name(snap, "b")
    assert sorted(calls) == sorted(world)
    assert not [f for f in audit.pin_parity(snap)[0] if "repin" in f["what"]]


def test_the_recorded_estate_names_seeder_as_the_one_consumer_without_repin():
    snap = json.loads((FIX / "estate-2026-10-29.json").read_text())
    repin = [f for f in audit.pin_parity(snap)[0] if "repin" in f["what"]]
    assert whats(repin) == [("seeder", "pins in-org git crates but has no `.github/workflows/repin.yaml`")]


# --------------------------------------------------------------------------
# 3. the hand-over to the route job
# --------------------------------------------------------------------------


def read_outputs(path):
    """Parse a $GITHUB_OUTPUT file: `k=v` lines and `k<<DELIM` blocks."""
    out, lines = {}, Path(path).read_text().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line:
            key, delim = line.split("<<", 1)
            end = lines.index(delim, i + 1)
            out[key] = "\n".join(lines[i + 1:end])
            i = end + 1
        elif "=" in line:
            key, value = line.split("=", 1)
            out[key] = value
            i += 1
        else:
            i += 1
    return out


@pytest.mark.parametrize("red", [False, True])
def test_check_writes_the_verdict_and_the_report_to_the_step_outputs(tmp_path, red):
    snap = pristine()
    if red:
        by_name(snap, "gateway")["proto"] = "v1.0.0"
    (tmp_path / "s.json").write_text(json.dumps(snap))
    outputs = tmp_path / "out"
    code = audit.main(["check", "--snapshot", str(tmp_path / "s.json"), "--outputs", str(outputs)])
    got = read_outputs(outputs)
    assert code == (1 if red else 0)
    assert got["verdict"] == ("red" if red else "green")
    assert got["report"] == audit.report(snap)[0].rstrip("\n")


def test_the_workflow_routes_a_red_run_from_a_separate_job():
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "audit.yaml").read_text())
    assert doc["permissions"] == {}
    jobs = doc["jobs"]
    # `secrets` is P3's (test_audit_secrets.py pins its one secret-reading step).
    assert set(jobs) == {"secrets", "audit", "route"}
    audit_job, route = jobs["audit"], jobs["route"]
    assert audit_job["permissions"] == {"contents": "read"}
    assert route["permissions"] == {"contents": "read", "issues": "write"}
    assert [n for n, j in jobs.items() if "issues" in j.get("permissions", {})] == ["route"]
    assert route["needs"] == "audit"
    assert "!cancelled()" in route["if"] and "refs/heads/main" in route["if"]
    assert route["runs-on"] == "ubuntu-latest"
    assert set(audit_job["outputs"]) == {"verdict", "report"}
    for job in jobs.values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w.\-]+/[\w.\-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"] == {"persist-credentials": False}
            if step.get("id") != "app":
                assert not SECRETS_CTX.search(str(step)), step.get("name")
            # zizmor template injection: expressions reach a script through env only.
            assert "${{" not in step.get("run", ""), step.get("name")
    judge = audit_job["steps"][-1]
    assert "--summary" in judge["run"] and "--outputs" in judge["run"]
    assert "audit_issue.py" in route["steps"][-1]["run"]
