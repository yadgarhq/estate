"""`scripts/audit.py`, the ADR-0561 auditor (yaadgaar 224).

Every predicate has a RED fixture and a PRISTINE companion that must report
nothing (ADR-0646): a sweep of red cases alone cannot tell a correct rule from
one too weak to fire, nor from one that fires on everything.

`fixtures/audit/estate-2026-10-29.json` is a real snapshot, written by
`audit.py gather --owner yadgarhq` on 2026-10-29 with a read-only token. Its
one later edit is mechanical: `actions_rev` became the list `actions_revs`
when the parser learned to read every `yadgarhq/actions` block.
`fixtures/audit/gateway-Cargo.lock` is gateway's real Cargo.lock on the same
day, cut down to its in-org git packages and one crates.io package.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
import yaml

import audit

FIX = Path(__file__).resolve().parent / "fixtures" / "audit"
ROOT = Path(__file__).resolve().parents[2]
RUST = ["cargo-fmt", "gitleaks", "boot-reads-watched"]


def repo(name, topics, hooks=None, lock=None, proto=None, rev="v1.0.0", **meta):
    base = {"name": name, "visibility": "public", "archived": False, "fork": False,
            "disabled": False, "topics": topics, "hooks": hooks, "lock_sources": lock,
            "proto": proto, "actions_revs": None if rev is None else [rev]}
    base.update(meta)
    return base


def pristine():
    """A tiny estate in which every predicate holds."""
    deps = [["dial", "v0.2.10"], ["lifecycle", "v0.3.2"]]
    return {
        "owner": "yadgarhq",
        "classes": {"exempt": {"actions": "producer"}, "sweep": {"exclude": {"docs": "private"}}},
        "tags": {"dial": ["v0.2.9", "v0.2.10", "v0.2.2"], "lifecycle": ["v0.3.2", "v0.3.0"],
                 "proto": ["v1.26.1"], "actions": ["v1.0.0", "v0.9.9"]},
        "repos": [
            repo("actions", [], hooks=["gitleaks"], rev=None),
            repo("gateway", ["yadgar-class-service", "yadgar-deployable"], RUST, deps, "v1.26.1"),
            repo("iam", ["yadgar-class-service", "yadgar-deployable"], RUST, deps, "v1.26.1"),
            repo("seeder", ["yadgar-class-rust-helm", "yadgar-deployable"], RUST + ["extra"], deps),
            repo("dial", ["yadgar-class-rust-helm"], ["cargo-fmt", "helm-lint"], []),
            repo("store", ["yadgar-class-rust-lib"], ["cargo-fmt"], []),
            repo("estate", ["yadgar-class-rust-app"], ["gitleaks"]),
        ],
    }


def by_name(snap, name):
    return next(r for r in snap["repos"] if r["name"] == name)


def whats(findings):
    return [(f["repo"], f["what"]) for f in findings]


# --------------------------------------------------------------------------
# versions
# --------------------------------------------------------------------------


def test_greatest_is_numeric_not_lexical():
    assert audit.greatest(["v0.2.9", "v0.2.10", "v0.2.2"]) == "v0.2.10"
    assert audit.greatest(["v1.9.0", "v1.10.0", "main", "v1.10.0-rc1"]) == "v1.10.0"
    assert audit.greatest(["main"]) is None


def test_semver_is_fullmatched():
    assert audit.semver("v1.2.3") == (1, 2, 3)
    for bad in ("v1.2.3\n", " v1.2.3", "1.2.3", "v1.2", None):
        assert audit.semver(bad) is None


# --------------------------------------------------------------------------
# parsers
# --------------------------------------------------------------------------


def test_lock_sources_key_on_the_source_url_tag_not_the_cargo_version():
    pins = audit.lock_sources((FIX / "gateway-Cargo.lock").read_text(), "yadgarhq")
    # Every one of these crates says `version = "0.1.0"` or so; the tag is the pin.
    assert pins == [("dial", "v0.2.25"), ("lifecycle", "v0.2.17"), ("telemetry", "v0.2.0")]


def test_lock_sources_report_a_git_source_with_no_tag():
    text = ('version = 4\n[[package]]\nname = "yadgar-store"\nversion = "0.6.4"\n'
            'source = "git+https://github.com/yadgarhq/store?rev=abc#abc"\n'
            '[[package]]\nname = "x"\nversion = "1.0.0"\n'
            'source = "git+https://github.com/elsewhere/x.git?tag=v9.9.9#d"\n')
    assert audit.lock_sources(text, "yadgarhq") == [("store", None)]


def test_pre_commit_reads_this_repositorys_own_config():
    revs, ids = audit.pre_commit((ROOT / ".pre-commit-config.yaml").read_text(), "yadgarhq")
    assert len(revs) == 1 and audit.semver(revs[0])
    assert {"gitleaks", "no-test-skips", "pytest-scripts", "trailing-whitespace"} <= set(ids)
    assert "hadolint" not in ids  # its header says why it is absent


def test_proto_pin_strips_the_newline():
    assert audit.proto_pin("v1.26.1\n") == "v1.26.1"
    assert audit.proto_pin(None) is None


# --------------------------------------------------------------------------
# enumeration and classes
# --------------------------------------------------------------------------


@pytest.mark.parametrize("topics, want", [
    (["yadgar-class-service", "yadgar-deployable"], "deployable"),
    (["yadgar-class-rust-helm", "yadgar-deployable"], "deployable"),
    (["yadgar-class-rust-helm"], "crate"),
    (["yadgar-class-rust-lib"], "crate"),
    (["yadgar-class-chart"], "chart"),
    (["yadgar-class-base"], "infra"),
    (["yadgar-class-rust-app"], "infra"),
])
def test_class_of(topics, want):
    assert audit.class_of(topics) == (want, None)


@pytest.mark.parametrize("topics", [[], ["yadgar-class-chart", "yadgar-class-base"], ["yadgar-class-nope"]])
def test_class_of_refuses_zero_several_or_unknown(topics):
    cls, why = audit.class_of(topics)
    assert cls is None and why


def test_the_sweep_is_public_live_and_not_excluded():
    cfg = {"sweep": {"exclude": {"docs": "private"}}}
    assert audit.in_sweep(repo("x", []), cfg)
    for meta in ({"visibility": "private"}, {"archived": True}, {"fork": True}, {"disabled": True},
                 {"name": "docs"}, {"archived": None}):
        r = repo("x", [])
        r.update(meta)
        assert not audit.in_sweep(r, cfg), meta


def test_the_auditor_sweeps_itself():
    snap = json.loads((FIX / "estate-2026-10-29.json").read_text())
    text, _ = audit.report(snap)
    _, classes = audit.hook_conformance(snap)
    assert "estate" in classes["infra"]["members"]
    assert "estate" in text.split("Swept", 1)[1].split("\n", 1)[0]


# --------------------------------------------------------------------------
# P1 — pin parity
# --------------------------------------------------------------------------


def test_p1_pristine_estate_has_no_findings():
    findings, table, latest = audit.pin_parity(pristine())
    assert findings == []
    assert latest["dial"] == "v0.2.10"
    assert table["dial"] == {"v0.2.10": ["gateway", "iam", "seeder"]}


def test_p1_a_pin_behind_the_latest_tag_fails():
    snap = pristine()
    by_name(snap, "iam")["lock_sources"] = [["dial", "v0.2.9"], ["lifecycle", "v0.3.2"]]
    findings, _, _ = audit.pin_parity(snap)
    assert whats(findings) == [("iam", "`dial` pinned at `v0.2.9`, latest `v0.2.10`")]


def test_p1_proto_and_actions_rev_behind_fail():
    snap = pristine()
    by_name(snap, "gateway")["proto"] = "v1.26.0"
    by_name(snap, "estate")["actions_revs"] = ["v0.9.9"]
    assert whats(audit.pin_parity(snap)[0]) == [
        ("estate", "`actions` pinned at `v0.9.9`, latest `v1.0.0`"),
        ("gateway", "`proto` pinned at `v1.26.0`, latest `v1.26.1`"),
    ]


def test_p1_an_untagged_source_and_an_untagged_producer_fail():
    snap = pristine()
    by_name(snap, "iam")["lock_sources"] = [["dial", None], ["lifecycle", "v0.3.2"], ["fresh", "v0.1.0"]]
    assert whats(audit.pin_parity(snap)[0]) == [
        ("iam", "`dial` is a git source with no `tag=`"),
        ("iam", "`fresh` has no released `vX.Y.Z` tag"),
    ]


def test_p1_ignores_repositories_outside_the_sweep():
    snap = pristine()
    for name, meta in (("iam", {"archived": True}), ("gateway", {"visibility": "private"})):
        by_name(snap, name).update(meta, proto="v0.0.1")
    assert audit.pin_parity(snap)[0] == []


# --------------------------------------------------------------------------
# P2 — hook-set conformance
# --------------------------------------------------------------------------


def test_p2_pristine_estate_has_no_findings():
    findings, classes = audit.hook_conformance(pristine())
    assert findings == []
    assert classes["deployable"]["members"] == ["gateway", "iam", "seeder"]
    assert set(classes["deployable"]["required"]) == set(RUST)
    # dial carries helm-lint and store does not: 1/2 is under 80%, so not required.
    assert set(classes["crate"]["required"]) == {"cargo-fmt"}
    assert "actions" not in str(classes)  # the producer is exempt


def test_p2_a_repository_missing_a_required_hook_fails_and_extras_pass():
    snap = pristine()
    by_name(snap, "seeder")["hooks"] = ["cargo-fmt", "gitleaks", "extra"]
    for name in ("gateway", "iam"):
        by_name(snap, name)["hooks"] = RUST
    for extra in ("w", "x", "y"):  # six members: 5/6 carry boot-reads-watched
        snap["repos"].append(repo(extra, ["yadgar-deployable"], RUST))
    findings, classes = audit.hook_conformance(snap)
    assert classes["deployable"]["required"]["boot-reads-watched"] == 5
    assert whats(findings) == [("seeder", "deployable: missing required `boot-reads-watched`")]


def test_p2_the_threshold_is_eighty_percent_inclusive():
    members = {str(i): ["a"] if i < 4 else [] for i in range(5)}
    assert audit.required(members) == {"a": 4}
    members["4"] = []
    members["5"] = []  # 4/6 = 67%
    assert audit.required(members) == {}
    assert audit.required({}) == {}


def test_p2_no_class_and_no_config_fail():
    snap = pristine()
    by_name(snap, "estate")["topics"] = []
    by_name(snap, "store")["hooks"] = None
    assert whats(audit.hook_conformance(snap)[0]) == [
        ("estate", "no class: 0 `yadgar-class-*` topics, need exactly one"),
        ("store", "no `.pre-commit-config.yaml`"),
    ]


# --------------------------------------------------------------------------
# the report, and the real estate as recorded
# --------------------------------------------------------------------------


def test_report_is_green_on_the_pristine_estate():
    text, code = audit.report(pristine())
    assert code == 0 and "**GREEN**" in text and "- none" in text


def test_the_recorded_estate_reproduces_the_known_drift():
    snap = json.loads((FIX / "estate-2026-10-29.json").read_text())
    text, code = audit.report(snap)
    p1, _, latest = audit.pin_parity(snap)
    p2, classes = audit.hook_conformance(snap)
    assert code == 1
    assert latest == {"actions": "v1.42.0", "dial": "v0.2.26", "lifecycle": "v0.3.2",
                      "proto": "v1.26.1", "store": "v0.6.4", "telemetry": "v0.2.7"}
    assert ("telemetry", "`proto` pinned at `v1.11.1`, latest `v1.26.1`") in whats(p1)
    assert ("gateway", "`lifecycle` pinned at `v0.2.17`, latest `v0.3.2`") in whats(p1)
    assert not [f for f in p1 if "`actions`" in f["what"]]
    assert len(p1) == 36
    assert whats(p2) == [("seeder", "deployable: missing required "
                                    "`boot-reads-watched`, `chart-baseline`, `chart-network-policy`")]
    assert classes["crate"]["members"] == ["dial", "lifecycle", "store", "telemetry"]
    assert "helm-lint" not in classes["crate"]["required"]
    assert classes["docs"]["members"] == []
    assert "36 pin finding(s), 1 hook finding(s)" in text


def test_check_writes_the_summary_and_exits_red(tmp_path):
    snap = tmp_path / "s.json"
    summary = tmp_path / "summary.md"
    snap.write_text(json.dumps(copy.deepcopy(pristine())))
    assert audit.main(["check", "--snapshot", str(snap), "--summary", str(summary)]) == 0
    bad = pristine()
    by_name(bad, "gateway")["proto"] = "v1.0.0"
    snap.write_text(json.dumps(bad))
    assert audit.main(["check", "--snapshot", str(snap), "--summary", str(summary)]) == 1
    assert summary.read_text().count("# ADR-0561 audit") == 2


def test_gather_reads_only_through_the_injected_getter():
    calls = []
    world = {
        "repos/o/actions/contents/classes.json": json.dumps({"exempt": {}, "sweep": {"exclude": {}}}),
        "orgs/o/repos?type=public&per_page=100&page=1": [
            {"name": "a", "visibility": "public", "archived": False, "fork": False, "disabled": False,
             "topics": ["yadgar-class-base"]},
            {"name": "old", "visibility": "public", "archived": True, "fork": False, "disabled": False,
             "topics": []}],
        "repos/o/a/contents/.pre-commit-config.yaml":
            "repos:\n  - repo: https://github.com/o/actions\n    rev: v1.0.0\n    hooks:\n      - id: g\n",
        "repos/o/a/contents/PROTO_VERSION": "v2.0.0\n",
        "repos/o/a/contents/Cargo.lock": None,
        "repos/o/actions/tags?per_page=100&page=1": [{"name": "v1.0.0"}],
        "repos/o/proto/tags?per_page=100&page=1": [{"name": "v2.0.0"}],
    }

    def get(path, raw=False):
        calls.append(path)
        return world[path]

    snap = audit.gather("o", get)
    a = by_name(snap, "a")
    assert (a["actions_revs"], a["hooks"], a["proto"], a["lock_sources"]) == (["v1.0.0"], ["g"], "v2.0.0", None)
    assert "hooks" not in by_name(snap, "old")  # archived: listed, never read
    assert snap["tags"] == {"actions": ["v1.0.0"], "proto": ["v2.0.0"]}
    assert audit.report(snap)[1] == 0
    assert len(calls) == len(world)


def test_the_workflow_is_read_only_scheduled_and_github_hosted():
    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "audit.yaml").read_text())
    on = doc.get("on", doc.get(True))
    assert set(on) == {"schedule", "workflow_dispatch"}
    assert doc["permissions"] == {}
    (job,) = doc["jobs"].values()
    assert job["runs-on"] == "ubuntu-latest"  # ADR-0563: never estate-front
    assert job["permissions"] == {"contents": "read"}
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w.\-]+/[\w.\-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"] == {"persist-credentials": False}
        assert "secrets." not in str(step)
    assert "--summary" in job["steps"][-1]["run"]


ACTIONS_BLOCK = "  - repo: https://github.com/yadgarhq/actions\n    rev: {}\n    hooks:\n      - id: {}\n"


def test_pre_commit_reads_every_actions_block():
    text = "repos:\n" + ACTIONS_BLOCK.format("v1.0.0", "a") + ACTIONS_BLOCK.format("v0.9.9", "b")
    assert audit.pre_commit(text, "yadgarhq") == (["v1.0.0", "v0.9.9"], ["a", "b"])


def test_p1_a_second_actions_block_behind_fails():
    snap = pristine()
    by_name(snap, "estate")["actions_revs"] = ["v1.0.0", "v0.9.9"]
    assert whats(audit.pin_parity(snap)[0]) == [("estate", "`actions` pinned at `v0.9.9`, latest `v1.0.0`")]
    by_name(snap, "estate")["actions_revs"] = ["v1.0.0", "v1.0.0"]
    findings, table, _ = audit.pin_parity(snap)
    assert findings == [] and table["actions"]["v1.0.0"].count("estate") == 1


def test_p1_an_unreadable_tag_list_is_a_finding():
    snap = pristine()
    snap["tags"]["dial"] = None
    assert whats(audit.pin_parity(snap)[0]) == [
        (name, "`dial`'s tag list is unreadable (404)") for name in ("gateway", "iam", "seeder")]


def listing(n, start=0):
    return [{"name": f"v0.0.{i}"} for i in range(start, start + n)]


def test_paged_follows_a_full_page_to_the_next():
    pages = {"r?per_page=100&page=1": listing(100), "r?per_page=100&page=2": listing(3, 100)}
    asked = []
    got = audit.paged(lambda path: asked.append(path) or pages[path], "r")
    assert len(got) == 103 and got[-1] == {"name": "v0.0.102"}
    assert asked == list(pages)


def test_paged_stops_on_a_short_page_and_refuses_an_endless_listing():
    assert audit.paged(lambda path: listing(99), "r") == listing(99)
    assert audit.paged(lambda path: [], "r") == []
    with pytest.raises(SystemExit, match="lists more than"):
        audit.paged(lambda path: listing(100), "r")


def test_paged_answers_none_for_a_missing_listing_and_refuses_a_missing_later_page():
    assert audit.paged(lambda path: None, "r") is None
    pages = {"r?per_page=100&page=1": listing(100), "r?per_page=100&page=2": None}
    with pytest.raises(SystemExit, match="not a listing"):
        audit.paged(lambda path: pages[path], "r")


def gather_world():
    return {
        "repos/o/actions/contents/classes.json": json.dumps({"exempt": {}, "sweep": {"exclude": {}}}),
        "orgs/o/repos?type=public&per_page=100&page=1": [
            {"name": "a", "visibility": "public", "archived": False, "fork": False, "disabled": False,
             "topics": ["yadgar-class-base"]}],
        "repos/o/a/contents/.pre-commit-config.yaml": None,
        "repos/o/a/contents/PROTO_VERSION": "v2.0.0\n",
        "repos/o/a/contents/Cargo.lock": None,
        "repos/o/proto/tags?per_page=100&page=1": None,
    }


def test_gather_records_a_404_tag_list_and_check_reports_it():
    world = gather_world()
    snap = audit.gather("o", lambda path, raw=False: world[path])
    assert snap["tags"] == {"proto": None}
    text, code = audit.report(snap)
    assert code == 1 and "`proto`'s tag list is unreadable (404)" in text


@pytest.mark.parametrize("missing, why", [
    ("repos/o/actions/contents/classes.json", "no classes.json"),
    ("orgs/o/repos?type=public&per_page=100&page=1", "no repository listing"),
])
def test_gather_refuses_without_its_inputs(missing, why):
    world = gather_world()
    world[missing] = None
    with pytest.raises(SystemExit, match=why):
        audit.gather("o", lambda path, raw=False: world[path])
