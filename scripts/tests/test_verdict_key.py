"""The render key K, and the public checks run before any verdict is trusted.

SHARED VECTORS (ruling 4, ADR-0844). The constants below are FROZEN HEX, not
recomputed: a test that derives its expected value from the code under test
proves nothing. argocd's `settled_gate.py` tests must assert these same
constants over the same fixture bytes (copied with `git show <sha>:<path>`,
never retyped), so a drift on either side is red on that side.

`13a2db6` and `eb43ea9` carry the same table blob (`2911480`) and the same
`applications/yadgar.yaml` blob (`87618dd`), so K at `eb43ea9` IS `K_13A2DB6`;
`test_verdict_anchor.py` relies on that.
"""

from __future__ import annotations

import pytest
from conftest import FIXTURES, SHA_13A, SHA_D41, fixture_files

import verdict

K_13A2DB6 = "2e275ae13256aae5d731c11a1e44a17e9a9bd6e815789c77cd86d20a5b950ee3"
K_D41C07F = "dc901cd764b3e8fdebba5d7a086544d89741c68d82c8876c8677cff947bfd942"
TRAP_K = "1b6a71c36fa07523feda3822718b321560a667b299152e61e052a9d7e4baf17a"
# argocd's own trap vector (`YAML_TRAPS` in argocd `scripts/tests/test_settled_gate.py`,
# argocd#63/#64 at e3f6643), written out byte for byte under fixtures/yaml-trap-argocd/.
ARGOCD_TRAP_K = "3a6bcb437e3ce19a7db3f616adfd22fc4e15d60cf152ee71eb98761d9b05a818"
ARGOCD_TRAP_CANONICAL = (
    b'{"chart":"yadgar","helm":{"valuesObject":{"big":"1e3","confirm":true,"enabled":true,'
    b'"mode":493,"name":"G\\u00f6teborg \\u2713","ratio":0.5}},'
    b'"repoURL":"ghcr.io/yadgarhq/charts","targetRevision":"0.3.38"}'
)
TRAP_CANONICAL = (
    b'{"chart":"yadgar","helm":{"valuesObject":{"answer":true,"empty":null,'
    b'"exponent":"1e3","mode":493,"name":"\\u00c5ngstr\\u00f6m \\u2713",'
    b'"negative":false,"nested":{"a_first":[3,"2",1.0],"z_last":1},'
    b'"octal_new":"0o755","ratio":0.5,"sexagesimal":80,"switch":true}},'
    b'"repoURL":"ghcr.io/yadgarhq/charts","targetRevision":"0.3.38"}'
)


@pytest.mark.parametrize("sha,want", [(SHA_13A, K_13A2DB6), (SHA_D41, K_D41C07F)])
def test_k_at_both_argocd_epochs_equals_the_shared_constant(sha, want):
    f = fixture_files(sha)
    assert verdict.render_key(f[verdict.TABLE_PATH], f[verdict.APP_PATH]) == want


def test_the_two_epochs_have_different_keys():
    assert K_13A2DB6 != K_D41C07F


def test_the_yaml_trap_vector_encodes_to_the_frozen_bytes():
    trap = FIXTURES.parent / "yaml-trap"
    app = (trap / "yadgar.yaml").read_bytes()
    table = (trap / "yadgar_render.sha256").read_bytes()
    assert verdict.canonical(verdict.spec_source(app)) == TRAP_CANONICAL
    assert verdict.render_key(table, app) == TRAP_K


def test_argocds_trap_vector_encodes_to_argocds_frozen_bytes():
    trap = FIXTURES.parent / "yaml-trap-argocd"
    app = (trap / "yadgar.yaml").read_bytes()
    table = (trap / "yadgar_render.sha256").read_bytes()
    assert verdict.canonical(verdict.spec_source(app)) == ARGOCD_TRAP_CANONICAL
    assert verdict.render_key(table, app) == ARGOCD_TRAP_K


def test_a_comment_only_edit_does_not_move_k():
    f = fixture_files(SHA_D41)
    edited = f[verdict.APP_PATH].replace(b"    chart: yadgar\n", b"    chart: yadgar  # a comment\n", 1)
    assert edited != f[verdict.APP_PATH]
    assert verdict.render_key(f[verdict.TABLE_PATH], edited) == K_D41C07F


@pytest.mark.parametrize(
    "values,named",
    [
        ("on: 1\n          off_label: 2", "True"),  # a YAML 1.1 bool key beside a string key
        ("1: one", "1"),
        ("released: 2026-10-03", "date"),
    ],
)
def test_what_canonical_json_cannot_carry_is_a_red_naming_the_field(values, named):
    app = (
        "spec:\n  source:\n    repoURL: ghcr.io/yadgarhq/charts\n    chart: yadgar\n"
        f"    targetRevision: 0.3.38\n    helm:\n      valuesObject:\n          {values}\n"
    ).encode()
    with pytest.raises(verdict.Red, match=named):
        verdict.render_key(b"targetRevision  0.3.38\n", app)


def test_both_fixtures_pass_the_consistency_checks():
    for sha, pin in ((SHA_13A, "0.3.13"), (SHA_D41, "0.3.38")):
        f = fixture_files(sha)
        assert verdict.check_consistency(f[verdict.APP_PATH], f[verdict.TABLE_PATH], f[verdict.PIN_PATH]) == pin


def _broken(edit):
    f = fixture_files(SHA_D41)
    app, table, pin = edit(f[verdict.APP_PATH], f[verdict.TABLE_PATH], f[verdict.PIN_PATH])
    return lambda: verdict.check_consistency(app, table, pin)


@pytest.mark.parametrize(
    "edit,named",
    [
        (lambda a, t, p: (a.replace(b"repoURL: ghcr.io/yadgarhq/charts", b"repoURL: ghcr.io/evil/charts"), t, p),
         "only 'ghcr.io/yadgarhq/charts'"),
        (lambda a, t, p: (a.replace(b"    chart: yadgar\n", b"    chart: other\n"), t, p), "chart 'other'"),
        (lambda a, t, p: (a.replace(b"    chart: yadgar\n", b"    chart: yadgar\n    path: x\n"), t, p),
         r"\['path'\]"),
        (lambda a, t, p: (a, t.replace(b"targetRevision  0.3.38", b"targetRevision  0.3.37"), p),
         "first data line"),
        (lambda a, t, p: (a, t, p.replace(b"v0.3.38", b"v0.3.37")), "chart_tag is 'v0.3.37'"),
        (lambda a, t, p: (a.replace(b"targetRevision: 0.3.38", b"targetRevision: 0.3.37"), t, p),
         "first data line"),
    ],
)
def test_a_consistency_mismatch_is_red_with_the_mismatch_named(edit, named):
    with pytest.raises(verdict.Red, match=named):
        _broken(edit)()
