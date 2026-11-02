"""The estate#55 review's follow-ups (yaadgaar #477, folded into #362).

1. THE REPORT OUTPUT IS BOUNDED IN BYTES. The `route` job receives the report
   as the `REPORT` environment variable. Linux refuses an `execve` whose single
   environment string exceeds MAX_ARG_STRLEN (131072 bytes), so an unbounded
   report fails the route step before `audit_issue.py` runs and a red run is
   not routed. `check` cuts the report OUTPUT by UTF-8 bytes; the step summary
   keeps all of it.
2. ONE BAD FILE IS A FINDING, NOT A CRASH. A consumer's `.pre-commit-config.yaml`
   or `repin.yaml` that does not parse, or parses to the wrong shape, used to
   raise out of `gather` and route the whole estate as `crash`. It is now a
   finding against that one repository, and every other repository is judged.
3. THE ROUTE STEP'S ENVIRONMENT IS PINNED EXACTLY, so a renamed output cannot
   route every run as `crash` while the tests stay green.

Every rule has a red case and a pristine companion (ADR-0646).
"""

from __future__ import annotations

import json
import re

import pytest
import yaml

import audit
from test_audit import ROOT, by_name, pristine, whats
from test_audit_routing import CALLER, read_outputs

ENV_LIMIT = 131072  # Linux MAX_ARG_STRLEN, one environment string, NUL included


# --------------------------------------------------------------------------
# 1. the report output fits one environment string
# --------------------------------------------------------------------------


def test_a_short_report_passes_through_unchanged():
    text = "# ADR-0561 audit\n\n**GREEN** — none.\n"
    assert audit.cut_for_env(text) == text


def test_a_report_over_the_limit_is_cut_by_bytes_not_characters():
    # Three-byte characters: a character cut at the limit would be three times over.
    text = "— " * 100_000
    cut = audit.cut_for_env(text)
    assert len(("REPORT=" + cut).encode("utf-8")) + 1 <= ENV_LIMIT
    assert len(cut.encode("utf-8")) <= audit.REPORT_OUTPUT_MAX_BYTES
    assert "report cut at" in cut and "step summary" in cut
    cut.encode("utf-8").decode("utf-8")  # no split character


def test_the_bound_leaves_room_for_the_name_and_the_nul():
    assert audit.REPORT_OUTPUT_MAX_BYTES + len("REPORT=") + 1 <= ENV_LIMIT


def test_check_cuts_the_report_output_and_keeps_the_summary_whole(tmp_path, monkeypatch):
    snap = pristine()
    by_name(snap, "gateway")["proto"] = "v1.0.0"
    (tmp_path / "s.json").write_text(json.dumps(snap))
    huge = "x" * 70_000 + "— " * 40_000

    def fat_report(s, p3=None):
        return huge, 1

    monkeypatch.setattr(audit, "report", fat_report)
    outputs, summary = tmp_path / "out", tmp_path / "summary"
    code = audit.main(["check", "--snapshot", str(tmp_path / "s.json"),
                       "--outputs", str(outputs), "--summary", str(summary)])
    got = read_outputs(outputs)
    assert code == 1 and got["verdict"] == "red"
    assert len(got["report"].encode("utf-8")) <= audit.REPORT_OUTPUT_MAX_BYTES
    assert summary.read_text() == huge


# --------------------------------------------------------------------------
# 2. a malformed file is a finding against its repository
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "repos: [\n",                      # not YAML
    "- just\n- a list\n",              # not a mapping
    "repos: {a: 1}\n",                 # repos not a list
    "repos: [7]\n",                    # a block that is not a mapping
    "repos: [{repo: x, hooks: 3}]\n",  # hooks not a list
    "repos: [{repo: x, hooks: [{name: y}]}]\n",  # a hook with no id
    "repos: 2026-13-45\n",             # valid YAML, a timestamp that is no date
])
def test_pre_commit_refuses_a_malformed_config_as_unparsable(text):
    with pytest.raises(audit.Unparsable):
        audit.pre_commit(text, "yadgarhq")


@pytest.mark.parametrize("text", ["jobs: [\n", "- a\n", "jobs: [a, b]\n"])
def test_repin_callers_refuses_a_malformed_workflow_as_unparsable(text):
    with pytest.raises(audit.Unparsable):
        audit.repin_callers(text)


def test_a_parse_error_reason_never_quotes_the_source_line():
    with pytest.raises(audit.Unparsable) as exc:
        audit.pre_commit("repos:\n  - repo: x\n    rev: SECRET_VALUE_LINE: [\n", "yadgarhq")
    assert "SECRET_VALUE_LINE" not in str(exc.value)


@pytest.mark.parametrize("text, name", [
    ("repos: !SECRET_TAG x\n", "SECRET_TAG"),       # an unknown tag
    ("repos: *SECRETALIAS\n", "SECRETALIAS"),       # an undefined alias
])
def test_a_parse_error_never_names_a_tag_or_alias_from_the_input(text, name):
    with pytest.raises(audit.Unparsable) as exc:
        audit.pre_commit(text, "yadgarhq")
    assert name not in str(exc.value)
    assert re.search(r"line \d+, column \d+", str(exc.value)), str(exc.value)
    # And through gather, into the finding a public log prints.
    world = malformed_world()
    snap = audit.gather("o", lambda path, raw=False: text if path.endswith("a/contents/.pre-commit-config.yaml")
                        else world(path, raw))
    found = audit.pin_parity(snap)[0] + audit.hook_conformance(snap)[0]
    assert found and not [f for f in found if name in f["what"]]


def test_a_valid_yaml_value_error_is_named_by_its_class_only():
    with pytest.raises(audit.Unparsable) as exc:
        audit.pre_commit("repos: 2026-13-45\n", "yadgarhq")
    assert str(exc.value) == "ValueError"


def malformed_world(bad_pre_commit=False, bad_repin=False):
    lock = ('version = 4\n[[package]]\nname = "yadgar-dial"\nversion = "0.1.0"\n'
            'source = "git+https://github.com/o/dial?tag=v0.1.0#abc"\n')
    ok_cfg = ("repos:\n  - repo: https://github.com/o/actions\n    rev: v1.0.0\n"
              "    hooks: [{id: gitleaks}]\n")
    world = {
        "repos/o/actions/contents/classes.json": json.dumps({"exempt": {}, "sweep": {"exclude": {}}}),
        "orgs/o/repos?type=public&per_page=100&page=1": [
            {"name": n, "visibility": "public", "archived": False, "fork": False, "disabled": False,
             "topics": ["yadgar-class-base"]} for n in ("a", "b")],
        "repos/o/a/contents/.pre-commit-config.yaml": "repos: [\n" if bad_pre_commit else ok_cfg,
        "repos/o/a/contents/PROTO_VERSION": None,
        "repos/o/a/contents/Cargo.lock": lock,
        "repos/o/a/contents/.github/workflows/repin.yaml":
            "jobs: [\n" if bad_repin else f"jobs:\n  r:\n    uses: {CALLER.replace('yadgarhq', 'o')}\n",
        "repos/o/b/contents/.pre-commit-config.yaml": ok_cfg,
        "repos/o/b/contents/PROTO_VERSION": None,
        "repos/o/b/contents/Cargo.lock": None,
        "repos/o/dial/tags?per_page=100&page=1": [{"name": "v0.1.0"}],
        "repos/o/actions/tags?per_page=100&page=1": [{"name": "v1.0.0"}],
    }
    return lambda path, raw=False: world[path]


def test_the_pristine_world_is_green():
    snap = audit.gather("o", malformed_world())
    assert audit.pin_parity(snap)[0] == [] and audit.hook_conformance(snap)[0] == []


def test_a_bad_pre_commit_config_is_a_finding_and_the_rest_is_still_judged():
    snap = audit.gather("o", malformed_world(bad_pre_commit=True))
    p1 = whats(audit.pin_parity(snap)[0])
    p2 = whats(audit.hook_conformance(snap)[0])
    assert len(p1) == 1 and p1[0][0] == "a" and "`.pre-commit-config.yaml` does not parse" in p1[0][1]
    assert len(p2) == 1 and p2[0][0] == "a" and "`.pre-commit-config.yaml` does not parse" in p2[0][1]
    assert "no `.pre-commit-config.yaml`" not in p2[0][1]
    assert by_name(snap, "b")["hooks"] == ["gitleaks"]
    assert audit.report(snap)[1] == 1


def test_a_bad_repin_caller_is_a_finding_not_a_missing_file():
    snap = audit.gather("o", malformed_world(bad_repin=True))
    p1 = whats(audit.pin_parity(snap)[0])
    assert len(p1) == 1 and p1[0][0] == "a"
    assert "`.github/workflows/repin.yaml` does not parse" in p1[0][1]
    assert "has no" not in p1[0][1]


def test_the_unreadable_record_survives_the_snapshot_round_trip(tmp_path):
    snap = json.loads(json.dumps(audit.gather("o", malformed_world(bad_pre_commit=True))))
    assert by_name(snap, "a")["unreadable"]
    assert audit.report(snap)[1] == 1


# --------------------------------------------------------------------------
# 3. the route step's environment, exactly
# --------------------------------------------------------------------------


def test_the_route_step_reads_exactly_the_audit_jobs_outputs():
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "audit.yaml").read_text())
    audit_job, route = doc["jobs"]["audit"], doc["jobs"]["route"]
    judge = audit_job["steps"][-1]
    assert judge["id"] == "judge"
    assert audit_job["outputs"] == {
        "verdict": "${{ steps.judge.outputs.verdict }}",
        "report": "${{ steps.judge.outputs.report }}",
    }
    assert route["steps"][-1]["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "REPO": "${{ github.repository }}",
        "VERDICT": "${{ needs.audit.outputs.verdict }}",
        "REPORT": "${{ needs.audit.outputs.report }}",
        "RUN_URL": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}",
    }
