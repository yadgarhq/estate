"""A self-referencing YAML alias in the Application is a named refusal (yaadgaar #559).

PyYAML builds `loop: &x [*x]` as a list that contains itself. Walking it, in
`canonical` for the render key or in `mariadb_extra_services` for the C-18
guard, never ends, and Python raises RecursionError. Before #559 neither
`main` nor its callers caught that class: the job died on a traceback with no
`::error` and no summary. It failed closed, but it said nothing.

Each case below reaches the recursion at a different call site, and each must
end the same way: `main` returns 1, prints `::error title=verdict refused`,
writes `run=false` and a REFUSED summary, and names the class, never the value.
"""

from __future__ import annotations

import pytest

from conftest import ESTATE_ID, OWN_TOKEN, SHA_D41, VERIFY_TOKEN, d41_reference, fixture_files

import verdict

APP = fixture_files(SHA_D41)[verdict.APP_PATH]
VALUES = b"      valuesObject:\n"
TASK_DB = b"        task-db:\n"
DATABASE = b"          database:\n"


def with_values_loop() -> bytes:
    """A self-alias in `valuesObject`, outside every module's `database`."""
    assert APP.count(VALUES) == 1
    return APP.replace(VALUES, VALUES + b"        loop: &loop [*loop]\n", 1)


def with_database_loop() -> bytes:
    """A self-alias under `task-db.database`, where the C-18 guard walks."""
    at = APP.index(DATABASE, APP.index(TASK_DB)) + len(DATABASE)
    return APP[:at] + b"            loop: &dbloop [*dbloop]\n" + APP[at:]


def with_values_text_loop() -> bytes:
    """A self-alias inside `helm.values`, a string the render key never walks."""
    assert APP.count(VALUES) == 1
    return APP.replace(VALUES, b"      values: |\n        task-db:\n          database: &t [*t]\n" + VALUES, 1)


CASES = {
    "valuesObject": (with_values_loop, "spec.source"),
    "database": (with_database_loop, "spec.source.helm.valuesObject"),
    "values text": (with_values_text_loop, "spec.source.helm.values"),
}


def run_main(world, tmp_path, monkeypatch, app: bytes):
    world.route(f"/repos/{verdict.ARGOCD}/contents/{verdict.APP_PATH}?ref={SHA_D41}", app)
    (tmp_path / "reference.toml").write_bytes(d41_reference())
    monkeypatch.setattr(verdict, "REFERENCE_PATH", tmp_path / "reference.toml")
    out, summary = tmp_path / "out", tmp_path / "summary"
    env = {
        "GITHUB_REPOSITORY": "yadgarhq/estate", "GITHUB_REPOSITORY_ID": str(ESTATE_ID),
        "GITHUB_TOKEN": OWN_TOKEN, "VERDICT_TOKEN": VERIFY_TOKEN, "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    return verdict.main(env, world), out.read_text(), summary.read_text()


@pytest.mark.parametrize("case", sorted(CASES))
def test_the_fixture_really_loops(case):
    make, _ = CASES[case]
    doc = verdict.yaml.safe_load(make())
    helm = doc["spec"]["source"]["helm"]
    if case == "valuesObject":
        loop = helm["valuesObject"]["loop"]
    elif case == "database":
        loop = helm["valuesObject"]["task-db"]["database"]["loop"]
    else:
        loop = verdict.yaml.safe_load(helm["values"])["task-db"]["database"]
    assert loop[0] is loop


@pytest.mark.parametrize("case", sorted(CASES))
def test_a_self_referencing_alias_is_a_named_refusal(case, world, tmp_path, monkeypatch, capsys):
    make, where = CASES[case]
    code, out, summary = run_main(world, tmp_path, monkeypatch, make())
    printed = capsys.readouterr().out
    assert code == 1
    assert "run=false" in out
    assert "REFUSED" in summary
    assert "::error title=verdict refused::" in printed
    named = f"{where} nests without end (RecursionError)"
    assert named in printed and named in summary
    assert "loop" not in printed + summary


def test_the_render_key_names_the_recursion():
    with pytest.raises(verdict.Red, match=r"^spec\.source nests without end \(RecursionError\)"):
        verdict.render_key(b"", with_values_loop())


@pytest.mark.parametrize("case", ["database", "values text"])
def test_the_c18_guard_names_the_recursion_as_a_refusal_not_drift(case):
    make, where = CASES[case]
    with pytest.raises(verdict.Red, match=rf"^{where.replace('.', chr(92) + '.')} nests without end"):
        verdict.mariadb_extra_services(make())


def test_main_refuses_a_recursion_error_no_named_catch_saw(monkeypatch, tmp_path, capsys):
    """The backstop: a RecursionError from anywhere else is still a refusal."""
    def boom(*a, **k):
        raise RecursionError("value-that-must-not-print")

    monkeypatch.setattr(verdict, "decide", boom)
    env = {"GITHUB_REPOSITORY": "yadgarhq/estate", "GITHUB_REPOSITORY_ID": "2002",
           "GITHUB_OUTPUT": str(tmp_path / "out"), "GITHUB_STEP_SUMMARY": str(tmp_path / "sum"),
           "VERDICT_TOKEN": "t", "GITHUB_TOKEN": "t"}
    assert verdict.main(env) == 1
    assert "REFUSED" in (tmp_path / "sum").read_text()
    printed = capsys.readouterr().out + (tmp_path / "sum").read_text()
    assert "RecursionError" in printed
    assert "value-that-must-not-print" not in printed
