"""P3 of `scripts/audit.py`: the release App secrets reach every repository that uses them.

yaadgaar 324, option C (ruling, Max 2026-10-29), credential ruling of
2026-10-30: a read-only App `yadgarhq-audit` (Secrets: read, Metadata: read).

WHO NEEDS THEM is read, never listed by hand: a repository needs
`RELEASE_APP_CLIENT_ID` / `RELEASE_APP_PRIVATE_KEY` when one of its own
workflow files references `secrets.<name>` in a value, or hands
`secrets: inherit` to a `yadgarhq/actions` workflow. A comment or a
`workflow_call` declaration key is not a use.

`fixtures/audit/workflows/task-ci.yaml` and `task-repin.yaml` are
`yadgarhq/task`'s real workflow files at e39ff47 (2026-10-30). The API answers
below follow GitHub's shape for `GET /repos/{o}/{r}/actions/secrets` and
`.../actions/organization-secrets`: `{"total_count": n, "secrets": [{"name": ...}]}`.

Every rule has a red case and a pristine companion (ADR-0646).
"""

from __future__ import annotations

import json
import re

import pytest
import yaml

import audit
from test_audit import FIX, ROOT, SECRETS_CTX
from test_audit_routing import read_outputs

WF = FIX / "workflows"
BOTH = ["RELEASE_APP_CLIENT_ID", "RELEASE_APP_PRIVATE_KEY"]


def listing(*names, total=None):
    return {"total_count": len(names) if total is None else total,
            "secrets": [{"name": n, "created_at": "2026-10-01T00:00:00Z"} for n in names]}


# --------------------------------------------------------------------------
# who needs the secrets
# --------------------------------------------------------------------------


def test_the_real_task_workflows_need_both():
    assert audit.release_needs((WF / "task-ci.yaml").read_text(), "yadgarhq") == BOTH
    assert audit.release_needs((WF / "task-repin.yaml").read_text(), "yadgarhq") == BOTH


@pytest.mark.parametrize("text, want", [
    # A comment is not a use.
    ("# passes secrets.RELEASE_APP_CLIENT_ID\njobs: {}\n", []),
    # A `workflow_call` declaration KEY is not a use.
    ("on:\n  workflow_call:\n    secrets:\n      RELEASE_APP_CLIENT_ID: {required: false}\n"
     "      RELEASE_APP_PRIVATE_KEY: {required: false}\njobs: {}\n", []),
    # One of the two is a need of that one only.
    ("jobs:\n  j:\n    runs-on: x\n    steps:\n      - env:\n"
     "          K: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}\n        run: echo\n", ["RELEASE_APP_PRIVATE_KEY"]),
    # Some other secret is not a need.
    ("jobs:\n  j:\n    uses: o/actions/.github/workflows/x.yaml@main\n    secrets:\n"
     "      T: ${{ secrets.RELEASE_APP_CLIENT_IDX }}\n", []),
    # `inherit` into the shared workflows hands over both.
    ("jobs:\n  j:\n    uses: o/actions/.github/workflows/ci-pr.yaml@main\n    secrets: inherit\n", BOTH),
    # `inherit` into somebody else's workflow is not this check's business.
    ("jobs:\n  j:\n    uses: other/repo/.github/workflows/x.yaml@main\n    secrets: inherit\n", []),
    ("", []),
    # Expression contexts are case-insensitive, and the index form is the same reference.
    ("jobs:\n  j:\n    uses: o/actions/.github/workflows/x.yaml@main\n    secrets:\n"
     "      A: ${{ SECRETS.release_app_client_id }}\n", ["RELEASE_APP_CLIENT_ID"]),
    ("jobs:\n  j:\n    uses: o/actions/.github/workflows/x.yaml@main\n    secrets:\n"
     "      A: ${{ secrets['RELEASE_APP_CLIENT_ID'] }}\n"
     "      B: ${{ secrets[\"release_app_private_key\"] }}\n", BOTH),
])
def test_release_needs(text, want):
    assert audit.release_needs(text, "o") == want


def needs_world():
    return {
        "repos/o/actions/contents/classes.json": json.dumps({"exempt": {}, "sweep": {"exclude": {"x": "private"}}}),
        "orgs/o/repos?type=public&per_page=100&page=1": [
            {"name": n, "visibility": "public", "archived": n == "old", "fork": False, "disabled": False,
             "topics": []} for n in ("task", "plain", "bare", "old", "x")],
        "repos/o/task/contents/.github/workflows": [
            {"type": "file", "name": "ci.yaml", "path": ".github/workflows/ci.yaml"},
            {"type": "file", "name": "repin.yml", "path": ".github/workflows/repin.yml"},
            {"type": "file", "name": "README.md", "path": ".github/workflows/README.md"},
            {"type": "dir", "name": "sub.yaml", "path": ".github/workflows/sub.yaml"}],
        "repos/o/task/contents/.github/workflows/ci.yaml": (WF / "task-ci.yaml").read_text(),
        "repos/o/task/contents/.github/workflows/repin.yml": "jobs: {}\n",
        "repos/o/plain/contents/.github/workflows": [
            {"type": "file", "name": "ci.yaml", "path": ".github/workflows/ci.yaml"}],
        "repos/o/plain/contents/.github/workflows/ci.yaml": "jobs: {}\n",
        "repos/o/bare/contents/.github/workflows": None,
    }


def test_needs_reads_every_workflow_of_every_swept_repository_and_nothing_else():
    world, calls = needs_world(), []

    def get(path, raw=False):
        calls.append(path)
        return world[path]

    assert audit.needs("o", get) == ({"task": BOTH}, {})
    assert sorted(calls) == sorted(world)


def test_needs_records_a_workflow_that_does_not_parse_and_reads_on():
    world = needs_world()
    world["repos/o/plain/contents/.github/workflows/ci.yaml"] = "jobs: [unclosed\n"
    found, unreadable = audit.needs("o", lambda path, raw=False: world[path])
    assert found == {"task": BOTH}
    assert list(unreadable) == ["plain"]
    assert len(unreadable["plain"]) == 1 and unreadable["plain"][0].startswith(".github/workflows/ci.yaml: ")


def test_p3_an_unparsable_workflow_is_a_finding_naming_repo_and_file():
    d = doc({"a": BOTH}, {"a": {"org": BOTH, "repo": []}})
    d["unreadable"] = {"plain": [".github/workflows/ci.yaml: while parsing"]}
    got = [(f["repo"], f["what"]) for f in audit.p3_findings(d)]
    assert got == [("plain", "workflow `.github/workflows/ci.yaml` does not parse, so whether it uses "
                             "the release App secrets is unknown: while parsing")]


def test_needs_refuses_a_listed_workflow_it_cannot_read():
    world = needs_world()
    world["repos/o/plain/contents/.github/workflows/ci.yaml"] = None
    with pytest.raises(SystemExit, match="plain.*ci.yaml"):
        audit.needs("o", lambda path, raw=False: world[path])


# --------------------------------------------------------------------------
# reading visibility: names only, fail closed
# --------------------------------------------------------------------------


def test_secret_names_pages_an_object_listing():
    pages = {"p?per_page=100&page=1": listing(*[f"S{i}" for i in range(100)], total=101),
             "p?per_page=100&page=2": listing("S100", total=101)}
    asked = []
    got = audit.listed_names(lambda path: asked.append(path) or pages[path], "p")
    assert got == sorted(f"S{i}" for i in range(101))
    assert asked == list(pages)


def test_secret_names_stops_on_a_short_page():
    assert audit.listed_names(lambda path: listing("B", "A"), "p") == ["A", "B"]
    assert audit.listed_names(lambda path: listing(), "p") == []


@pytest.mark.parametrize("answer, why", [
    (None, "404"),  # the App is not installed there, or lacks Secrets: read
    ([], "not a secret listing"),
    ({"total_count": 1}, "not a secret listing"),
])
def test_secret_names_refuses_what_is_not_a_listing(answer, why):
    with pytest.raises(SystemExit, match=why):
        audit.listed_names(lambda path: answer, "p")


def vis_world():
    return {
        "repos/o/a/actions/organization-secrets?per_page=100&page=1": listing(*BOTH),
        "repos/o/a/actions/secrets?per_page=100&page=1": listing(),
        "repos/o/b/actions/organization-secrets?per_page=100&page=1": listing("ORG_OTHER", "RELEASE_APP_CLIENT_ID"),
        "repos/o/b/actions/secrets?per_page=100&page=1": listing("RELEASE_APP_PRIVATE_KEY", "OTHER"),
        # A 404 on the first listing ends that repository: it is already a finding.
        "repos/o/c/actions/organization-secrets?per_page=100&page=1": None,
    }


def test_visibility_reads_both_listings_per_repository_and_records_an_error_per_repository():
    world, calls = vis_world(), []

    def get(path, raw=False):
        calls.append(path)
        if path.startswith("repos/o/d/"):
            raise SystemExit("gh api repos/o/d/actions/secrets: HTTP 403")
        return world[path]

    got = audit.visibility("o", ["a", "b", "c", "d"], get)
    assert got["a"] == {"org": BOTH, "repo": []}
    # ONLY the two release names leave this function: the document becomes a job
    # output and a step env value, both readable in this public repository's logs.
    assert got["b"] == {"org": ["RELEASE_APP_CLIENT_ID"], "repo": ["RELEASE_APP_PRIVATE_KEY"]}
    assert "404" in got["c"]["error"]
    assert "HTTP 403" in got["d"]["error"]
    assert sorted(c for c in calls if not c.startswith("repos/o/d/")) == sorted(world)


# --------------------------------------------------------------------------
# P3 — the predicate
# --------------------------------------------------------------------------


def doc(needs, vis):
    return {"owner": "o", "needs": needs, "visibility": vis}


def test_p3_pristine_org_visible_and_repo_level_both_pass():
    d = doc({"a": BOTH, "b": BOTH},
            {"a": {"org": BOTH, "repo": []},
             "b": {"org": ["RELEASE_APP_CLIENT_ID"], "repo": ["RELEASE_APP_PRIVATE_KEY"]}})
    assert audit.p3_findings(d) == []


@pytest.mark.parametrize("vis, missing", [
    ({"org": [], "repo": []}, BOTH),
    ({"org": ["RELEASE_APP_CLIENT_ID"], "repo": []}, ["RELEASE_APP_PRIVATE_KEY"]),
    ({"org": [], "repo": ["RELEASE_APP_PRIVATE_KEY", "OTHER"]}, ["RELEASE_APP_CLIENT_ID"]),
])
def test_p3_a_repository_that_sees_neither_or_one_fails_naming_each_secret(vis, missing):
    got = audit.p3_findings(doc({"a": BOTH}, {"a": vis}))
    assert [(f["predicate"], f["repo"]) for f in got] == [("P3", "a")] * len(missing)
    for f, name in zip(got, missing):
        assert f"`{name}`" in f["what"] and "neither" in f["what"]


def test_p3_a_repository_needing_one_is_judged_on_that_one():
    d = doc({"a": ["RELEASE_APP_PRIVATE_KEY"]}, {"a": {"org": ["RELEASE_APP_PRIVATE_KEY"], "repo": []}})
    assert audit.p3_findings(d) == []


def test_p3_an_api_error_or_an_unread_repository_is_a_finding_not_a_skip():
    d = doc({"a": BOTH, "b": BOTH}, {"a": {"error": "gh api x: HTTP 502"}})
    got = [(f["repo"], f["what"]) for f in audit.p3_findings(d)]
    assert got == [("a", "secret visibility unreadable: gh api x: HTTP 502"),
                   ("b", "secret visibility was not read")]


@pytest.mark.parametrize("bad", [{}, {"owner": "o"}, {"needs": None}, {"needs": {}, "visibility": None}])
def test_p3_an_unread_secrets_job_is_an_estate_finding(bad):
    got = audit.p3_findings(bad)
    assert len(got) == 1 and got[0]["predicate"] == "P3" and got[0]["repo"] == "(estate)"


def test_report_counts_p3_and_goes_red(tmp_path):
    from test_audit import pristine
    snap = tmp_path / "s.json"
    snap.write_text(json.dumps(pristine()))
    good = tmp_path / "good.json"
    good.write_text(json.dumps(doc({"a": BOTH}, {"a": {"org": BOTH, "repo": []}})))
    out = tmp_path / "out"
    assert audit.main(["check", "--snapshot", str(snap), "--secrets", str(good), "--outputs", str(out)]) == 0
    assert "0 secret finding(s)" in read_outputs(out)["report"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc({"a": BOTH}, {"a": {"org": [], "repo": []}})))
    out2 = tmp_path / "out2"
    assert audit.main(["check", "--snapshot", str(snap), "--secrets", str(bad), "--outputs", str(out2)]) == 1
    got = read_outputs(out2)
    assert got["verdict"] == "red" and "2 secret finding(s)" in got["report"]
    assert "P3 `a`: `RELEASE_APP_CLIENT_ID`" in got["report"]


@pytest.mark.parametrize("content", ["", "not json", "null"])
def test_check_treats_an_empty_or_broken_secrets_file_as_red(tmp_path, content):
    from test_audit import pristine
    snap = tmp_path / "s.json"
    snap.write_text(json.dumps(pristine()))
    f = tmp_path / "v.json"
    f.write_text(content)
    assert audit.main(["check", "--snapshot", str(snap), "--secrets", str(f)]) == 1


# --------------------------------------------------------------------------
# the CLI hand-over inside the `secrets` job
# --------------------------------------------------------------------------


def test_needs_command_writes_the_repositories_and_refuses_an_empty_list(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "needs", lambda owner, get=None: (
        {"b": BOTH, "a": ["RELEASE_APP_CLIENT_ID"]}, {"c": ["x.yaml: bad"]}))
    out, f = tmp_path / "out", tmp_path / "needs.json"
    assert audit.main(["needs", "--owner", "o", "--out", str(f), "--outputs", str(out)]) == 0
    assert read_outputs(out)["repos"] == "a,b"
    assert json.loads(f.read_text()) == {"needs": {"a": ["RELEASE_APP_CLIENT_ID"], "b": BOTH},
                                         "unreadable": {"c": ["x.yaml: bad"]}}
    # An empty `repositories:` beside `owner:` would mint for every repository.
    monkeypatch.setattr(audit, "needs", lambda owner, get=None: ({}, {"c": ["x.yaml: bad"]}))
    with pytest.raises(SystemExit, match="refused"):
        audit.main(["needs", "--owner", "o", "--out", str(f), "--outputs", str(out)])


def test_secrets_command_hands_needs_and_visibility_on_as_one_line(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "visibility", lambda owner, names, get=None: {n: {"org": BOTH, "repo": []} for n in names})
    f, out = tmp_path / "needs.json", tmp_path / "out"
    f.write_text(json.dumps({"needs": {"a": BOTH}, "unreadable": {}}))
    assert audit.main(["secrets", "--owner", "o", "--needs", str(f), "--outputs", str(out)]) == 0
    got = json.loads(read_outputs(out)["visibility"])
    assert got == dict(doc({"a": BOTH}, {"a": {"org": BOTH, "repo": []}}), unreadable={})
    assert audit.p3_findings(got) == []


# --------------------------------------------------------------------------
# the workflow: the key reaches the minting action and nothing else
# --------------------------------------------------------------------------


def workflow():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "audit.yaml").read_text())


def test_only_the_secrets_job_holds_the_audit_environment_and_only_its_mint_step_reads_a_secret():
    jobs = workflow()["jobs"]
    assert set(jobs) == {"secrets", "audit", "route"}
    assert [n for n, j in jobs.items() if "environment" in j] == ["secrets"]
    assert jobs["secrets"]["environment"] == "audit"
    assert jobs["secrets"]["permissions"] == {"contents": "read"}
    assert jobs["secrets"]["runs-on"] == "ubuntu-latest"
    readers = [(n, s) for n, j in jobs.items() for s in j["steps"] if SECRETS_CTX.search(str(s))]
    assert len(readers) == 1
    job, mint = readers[0]
    assert job == "secrets"
    assert re.fullmatch(r"actions/create-github-app-token@[0-9a-f]{40}", mint["uses"])
    assert set(re.findall(r"secrets\.(\w+)", str(mint))) == {"AUDIT_APP_CLIENT_ID", "AUDIT_APP_PRIVATE_KEY"}
    assert not SECRETS_CTX.search(str({k: v for k, v in mint.items() if k != "with"}))
    w = mint["with"]
    assert w["client-id"] == "${{ secrets.AUDIT_APP_CLIENT_ID }}"
    assert w["private-key"] == "${{ secrets.AUDIT_APP_PRIVATE_KEY }}"
    # SCOPED: never an owner-wide token. `repositories:` comes from the needs step.
    assert "steps.needs.outputs.repos" in w["repositories"]
    assert {k for k in w if k.startswith("permission-")} == {"permission-secrets", "permission-metadata"}
    assert w["permission-secrets"] == "read" and w["permission-metadata"] == "read"


def test_the_secrets_job_mints_only_on_main():
    # A dispatch from another ref must not mint. A modified workflow on a branch
    # bypasses this `if`; the `audit` environment's main-only deployment-branch
    # policy is the control that holds then.
    assert workflow()["jobs"]["secrets"]["if"] == "github.ref == 'refs/heads/main'"


@pytest.mark.parametrize("result, says", [
    ("skipped", "the `secrets` job was skipped: it runs on `main` only"),
    ("failure", "job result: failure"),
])
def test_p3_names_why_the_secrets_job_answered_nothing(tmp_path, result, says):
    from test_audit import pristine
    snap = tmp_path / "s.json"
    snap.write_text(json.dumps(pristine()))
    f = tmp_path / "v.json"
    f.write_text("")
    out = tmp_path / "out"
    assert audit.main(["check", "--snapshot", str(snap), "--secrets", str(f),
                       "--secrets-result", result, "--outputs", str(out)]) == 1
    report = read_outputs(out)["report"]
    assert "P3 `(estate)`" in report and says in report


def test_the_secrets_job_reads_needs_with_the_run_token_and_visibility_with_the_app_token():
    steps = {s.get("id"): s for s in workflow()["jobs"]["secrets"]["steps"]}
    order = [s.get("id") for s in workflow()["jobs"]["secrets"]["steps"]]
    assert order.index("needs") < order.index("app") < order.index("read")
    assert steps["needs"]["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "audit.py needs" in steps["needs"]["run"]
    assert steps["read"]["env"]["GH_TOKEN"] == "${{ steps.app.outputs.token }}"
    assert "audit.py secrets" in steps["read"]["run"]
    assert workflow()["jobs"]["secrets"]["outputs"]["visibility"] == "${{ steps.read.outputs.visibility }}"


def test_the_audit_job_judges_p3_even_when_the_secrets_job_failed():
    jobs = workflow()["jobs"]
    a = jobs["audit"]
    assert a["needs"] == "secrets"
    assert "!cancelled()" in a["if"]
    assert a["permissions"] == {"contents": "read"}
    judge = a["steps"][-1]
    assert judge["env"]["SECRETS_DOC"] == "${{ needs.secrets.outputs.visibility }}"
    assert judge["env"]["SECRETS_RESULT"] == "${{ needs.secrets.result }}"
    assert '--secrets-result "$SECRETS_RESULT"' in judge["run"]
    assert "--secrets" in judge["run"] and "$SECRETS_DOC" in judge["run"]
    assert jobs["route"]["needs"] == "audit"


# --------------------------------------------------------------------------
# hardening (estate#59 review)
# --------------------------------------------------------------------------


def test_a_parse_error_never_quotes_the_workflows_source():
    # PyYAML's message quotes the offending line. That line can name a secret
    # that is not a release secret, and the reason reaches public logs.
    world = needs_world()
    world["repos/o/plain/contents/.github/workflows/ci.yaml"] = (
        "jobs:\n  j:\n    env:\n      x: ${{ secrets.OTHER_NAME }}: [\n")
    found, unreadable = audit.needs("o", lambda path, raw=False: world[path])
    why = unreadable["plain"][0]
    assert "OTHER_NAME" not in why and "secrets" not in why
    assert re.search(r"line \d+, column \d+", why), why


@pytest.mark.parametrize("bad", [["x"], "x", {"a": "not a list"}, {"a": [1]}])
def test_p3_a_malformed_unreadable_record_is_one_estate_finding(bad):
    d = doc({"a": BOTH}, {"a": {"org": BOTH, "repo": []}})
    d["unreadable"] = bad
    got = audit.p3_findings(d)
    assert [(f["predicate"], f["repo"]) for f in got] == [("P3", "(estate)")]


def test_inherit_into_the_shared_workflows_matches_the_owner_case_insensitively():
    text = "jobs:\n  j:\n    uses: YadgarHQ/Actions/.github/workflows/ci-pr.yaml@main\n    secrets: inherit\n"
    assert audit.release_needs(text, "yadgarhq") == BOTH
