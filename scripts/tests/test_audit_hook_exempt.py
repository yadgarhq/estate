"""`classes.json` `hook_exempt`: a per-repository, per-hook exemption from P2 (yaadgaar 707).

Max's ruling of 2026-11-25. seeder is in class `deployable`, and three hooks
its class carries do not apply to it (no watcher, a one-sync Job, a Job-only
chart: ADR-0584, ADR-0940). The whole-repository `exempt` would hide every P2
finding for seeder, so `hook_exempt` exempts ONE hook id for ONE repository:

- the id leaves that repository's `missing`, and nothing else moves: the
  repository still counts in the class's 80% threshold;
- the report names every applied exemption with its reason, so a suppressed
  finding stays visible;
- an entry that names a repository P2 does not judge, has an empty reason or
  an invisible character in it, exempts a hook the repository carries
  (stale), or exempts a hook its class does not require (unneeded: this also
  catches a typo'd id) is a P2 finding and is not applied; a value of the
  wrong shape is one finding and applies nothing (fail closed). An invisible
  character is one whose Unicode category is C* (Cc, Cf, Co, Cn, Cs), Zl or
  Zp; a reason with no other non-whitespace character counts as empty;
- an absent key, or `{}`, behaves exactly as before.

Every rule has a red case and a pristine companion (ADR-0646).
"""

from __future__ import annotations

import copy
import json

import pytest

import audit
from test_audit import FIX, RUST, by_name, gather_world, pristine, repo, whats

THREE = ("boot-reads-watched", "chart-baseline", "chart-network-policy")
REASONS = {
    "boot-reads-watched": "no watcher: the Job lives for one sync (ADR-0584)",
    "chart-baseline": "the chart renders a Job only (ADR-0940)",
    "chart-network-policy": "the chart renders a Job only (ADR-0940)",
}
SEEDER_P2 = ("seeder", "deployable: missing required "
                       "`boot-reads-watched`, `chart-baseline`, `chart-network-policy`")


def recorded():
    return json.loads((FIX / "estate-2026-10-29.json").read_text())


def with_exempt(snap, value):
    snap = copy.deepcopy(snap)
    snap["classes"]["hook_exempt"] = value
    return snap


def six():
    """pristine(), with six deployable members of which seeder alone lacks `boot-reads-watched`."""
    snap = pristine()
    by_name(snap, "seeder")["hooks"] = ["cargo-fmt", "gitleaks", "extra"]
    for extra in ("w", "x", "y"):
        snap["repos"].append(repo(extra, ["yadgar-deployable"], RUST))
    return snap


MISSING = ("seeder", "deployable: missing required `boot-reads-watched`")


def ten():
    """Ten deployable members; seeder lacks `boot-reads-watched` and `gitleaks`, gateway lacks `gitleaks`.

    `boot-reads-watched` is then 9/10 and `gitleaks` 8/10, so both stay required.
    """
    snap = pristine()
    by_name(snap, "seeder")["hooks"] = ["cargo-fmt"]
    by_name(snap, "gateway")["hooks"] = ["cargo-fmt", "boot-reads-watched"]
    for extra in ("z1", "z2", "z3", "z4", "z5", "z6", "z7"):
        snap["repos"].append(repo(extra, ["yadgar-deployable"], RUST))
    return snap


# --------------------------------------------------------------------------
# AC5 — an absent key, or {}, behaves exactly as today
# --------------------------------------------------------------------------


def test_the_recorded_fixture_has_no_hook_exempt_key():
    assert "hook_exempt" not in recorded()["classes"]


@pytest.mark.parametrize("snap", [recorded(), with_exempt(recorded(), {})], ids=["absent", "empty"])
def test_absent_or_empty_hook_exempt_still_produces_todays_seeder_p2(snap):
    findings, classes = audit.hook_conformance(snap)
    assert whats(findings) == [SEEDER_P2]
    assert all(c["exempted"] == {} for c in classes.values())


def test_absent_and_empty_hook_exempt_write_the_same_report():
    assert audit.report(recorded()) == audit.report(with_exempt(recorded(), {}))
    assert "hook_exempt" not in audit.report(recorded())[0]


# --------------------------------------------------------------------------
# AC2 / AC3 — an applied exemption, on the recorded estate
# --------------------------------------------------------------------------


def test_exempting_seeders_three_hooks_clears_its_p2_and_names_each_with_its_reason():
    snap = with_exempt(recorded(), {"seeder": dict(REASONS)})
    findings, classes = audit.hook_conformance(snap)
    assert findings == []
    assert classes["deployable"]["exempted"] == {"seeder": REASONS}
    text, _ = audit.report(snap)
    assert "0 hook finding(s)" in text
    assert "`hook_exempt`" in text
    for hook, why in REASONS.items():
        assert f"- `seeder` `{hook}`: {why}" in text


def test_exempting_two_of_three_still_reports_the_third():
    two = {h: REASONS[h] for h in THREE[:2]}
    findings, classes = audit.hook_conformance(with_exempt(recorded(), {"seeder": two}))
    assert whats(findings) == [("seeder", "deployable: missing required `chart-network-policy`")]
    assert classes["deployable"]["exempted"] == {"seeder": two}


def test_an_exemption_does_not_move_the_class_threshold():
    _, before = audit.hook_conformance(recorded())
    _, after = audit.hook_conformance(with_exempt(recorded(), {"seeder": dict(REASONS)}))
    for cls in audit.CLASSES:
        assert after[cls]["required"] == before[cls]["required"]
        assert after[cls]["members"] == before[cls]["members"]
    assert "seeder" in after["deployable"]["members"]


def test_an_exemption_for_one_repository_leaves_the_others_judged():
    snap = six()
    for extra in ("z1", "z2", "z3", "z4"):  # ten members
        snap["repos"].append(repo(extra, ["yadgar-deployable"], RUST))
    by_name(snap, "y")["hooks"] = ["cargo-fmt", "gitleaks"]  # 8/10 carry boot-reads-watched
    findings, classes = audit.hook_conformance(with_exempt(snap, {"seeder": {"boot-reads-watched": "why"}}))
    assert classes["deployable"]["required"]["boot-reads-watched"] == 8
    assert whats(findings) == [("y", "deployable: missing required `boot-reads-watched`")]


def test_the_report_lists_exemptions_sorted_by_repository_then_hook():
    snap = with_exempt(ten(), {"seeder": {"gitleaks": "g", "boot-reads-watched": "b"},
                               "gateway": {"gitleaks": "z"}})
    findings, _ = audit.hook_conformance(snap)
    assert findings == []
    text, _ = audit.report(snap)
    lines = [ln for ln in text.splitlines() if ln.startswith("- `")]
    assert lines == ["- `gateway` `gitleaks`: z", "- `seeder` `boot-reads-watched`: b", "- `seeder` `gitleaks`: g"]


# --------------------------------------------------------------------------
# Max ruled 2026-11-25: an exemption for a hook the class does not require is
# refused as unneeded. It would suppress nothing, and a typo'd id lands here.
# --------------------------------------------------------------------------


def unneeded(name, hook, cls):
    return ("(estate)", f"`hook_exempt` `{hook}` for `{name}` is unneeded: class `{cls}` does not require it")


@pytest.mark.parametrize("hook", ["boot-reads-watche", "boot-reads-watched ", " boot-reads-watched",
                                  "Boot-Reads-Watched"])
def test_a_typod_hook_id_is_refused_as_unneeded_and_the_real_finding_stands(hook):
    findings, classes = audit.hook_conformance(with_exempt(six(), {"seeder": {hook: "why"}}))
    assert whats(findings) == [unneeded("seeder", hook, "deployable"), MISSING]
    assert classes["deployable"]["exempted"] == {}


def test_a_real_hook_the_class_does_not_require_is_refused_as_unneeded():
    # dial carries helm-lint and store does not: 1/2 is under 80%, so not required.
    snap = with_exempt(pristine(), {"store": {"helm-lint": "a library ships no chart"}})
    findings, classes = audit.hook_conformance(snap)
    assert whats(findings) == [unneeded("store", "helm-lint", "crate")]
    assert classes["crate"]["exempted"] == {}
    text, code = audit.report(snap)
    assert code == 1 and "a library ships no chart" not in text


def test_unneeded_is_judged_against_the_repositorys_own_class():
    # `boot-reads-watched` is required in deployable, not in store's class crate.
    findings, classes = audit.hook_conformance(with_exempt(pristine(), {"store": {"boot-reads-watched": "why"}}))
    assert whats(findings) == [unneeded("store", "boot-reads-watched", "crate")]
    assert all(c["exempted"] == {} for c in classes.values())


def test_unneeded_is_judged_per_entry_and_the_needed_one_still_applies():
    snap = with_exempt(recorded(), {"seeder": {**REASONS, "chart-baseline ": "typo"}})
    findings, classes = audit.hook_conformance(snap)
    assert whats(findings) == [unneeded("seeder", "chart-baseline ", "deployable")]
    assert classes["deployable"]["exempted"] == {"seeder": REASONS}


def test_the_recorded_seeder_three_are_all_required_so_none_is_unneeded():
    _, classes = audit.hook_conformance(recorded())
    assert set(THREE) <= set(classes["deployable"]["required"])
    findings, classes = audit.hook_conformance(with_exempt(recorded(), {"seeder": dict(REASONS)}))
    assert not [f for f in findings if "unneeded" in f["what"]]
    assert classes["deployable"]["exempted"] == {"seeder": REASONS}


def test_a_pristine_estate_with_no_exemption_writes_no_exemption_lines():
    text, code = audit.report(pristine())
    assert code == 0 and "hook_exempt" not in text


# --------------------------------------------------------------------------
# AC4 — refusals: a finding, never a crash, and the entry is not applied
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name, meta", [
    ("nobody", None),                       # absent from the snapshot
    ("docs", {"visibility": "private"}),    # outside the sweep
    ("actions", None),                      # whole-repository exempt
])
def test_an_entry_for_a_repository_p2_does_not_judge_is_a_finding(name, meta):
    snap = six()
    if meta is not None:
        snap["repos"].append(repo(name, ["yadgar-deployable"], RUST, **meta))
    snap = with_exempt(snap, {name: {"boot-reads-watched": "why"}, "seeder": {"boot-reads-watched": "why"}})
    findings, classes = audit.hook_conformance(snap)
    assert whats(findings) == [("(estate)", f"`hook_exempt` names `{name}`, a repository P2 does not judge")]
    assert classes["deployable"]["exempted"] == {"seeder": {"boot-reads-watched": "why"}}


@pytest.mark.parametrize("reason", ["", "   ", "\t", "\u200b", " \u200b\u200b ", "\u202e", "\x85",
                                    "\u2028\u2029", "\ufeff"])
def test_an_empty_reason_is_a_finding_and_the_exemption_is_not_applied(reason):
    findings, classes = audit.hook_conformance(with_exempt(six(), {"seeder": {"boot-reads-watched": reason}}))
    assert whats(findings) == [("seeder", "`hook_exempt` `boot-reads-watched` has an empty reason"), MISSING]
    assert classes["deployable"]["exempted"] == {}


@pytest.mark.parametrize("reason", [
    "line one\n## injected", "bell\x07", "del\x7f",
    "nel\x85next",          # Cc, C1
    "ls\u2028next",          # Zl
    "ps\u2029next",          # Zp
    "rlo\u202ereversed",     # Cf, bidi override
    "zw\u200bsp",            # Cf, zero-width space
    "private\ue000use",      # Co
    "unassigned\u0378",      # Cn
    "surrogate\ud800",       # Cs
])
def test_a_control_character_in_the_reason_is_a_finding_and_is_never_printed(reason):
    snap = with_exempt(six(), {"seeder": {"boot-reads-watched": reason}})
    findings, classes = audit.hook_conformance(snap)
    assert whats(findings) == [
        ("seeder", "`hook_exempt` `boot-reads-watched` has a forbidden character in its reason "
                   "(Unicode category C*, Zl or Zp)"), MISSING]
    assert classes["deployable"]["exempted"] == {}
    assert reason not in audit.report(snap)[0]


def test_a_stale_exemption_for_a_hook_the_repository_carries_is_a_finding():
    findings, classes = audit.hook_conformance(with_exempt(six(), {"seeder": {"gitleaks": "why"}}))
    assert whats(findings) == [("seeder", "`hook_exempt` `gitleaks` is stale: `seeder` carries it"), MISSING]
    assert classes["deployable"]["exempted"] == {}


def test_refusals_are_sorted_by_repository_then_hook():
    snap = with_exempt(six(), {"seeder": {"gitleaks": "x", "cargo-fmt": "x"}, "gateway": {"gitleaks": ""}})
    assert whats(audit.hook_conformance(snap)[0]) == [
        ("gateway", "`hook_exempt` `gitleaks` has an empty reason"),
        ("seeder", "`hook_exempt` `cargo-fmt` is stale: `seeder` carries it"),
        ("seeder", "`hook_exempt` `gitleaks` is stale: `seeder` carries it"),
        MISSING,
    ]


def test_a_member_with_no_config_can_be_exempted():
    snap = six()
    by_name(snap, "seeder")["hooks"] = None
    findings, classes = audit.hook_conformance(with_exempt(snap, {"seeder": {"boot-reads-watched": "why"}}))
    assert whats(findings) == [("seeder", "no `.pre-commit-config.yaml`"),
                               ("seeder", "deployable: missing required `cargo-fmt`, `gitleaks`")]
    assert classes["deployable"]["exempted"] == {"seeder": {"boot-reads-watched": "why"}}


@pytest.mark.parametrize("change, own", [
    ({"topics": []}, "no class: 0 `yadgar-class-*` topics, need exactly one"),
    ({"unreadable": {".pre-commit-config.yaml": "bad yaml"}}, "`.pre-commit-config.yaml` does not parse: bad yaml"),
])
def test_a_swept_repository_that_is_not_a_member_gets_no_extra_finding_and_no_exemption(change, own):
    snap = pristine()
    by_name(snap, "estate").update(change)
    findings, classes = audit.hook_conformance(with_exempt(snap, {"estate": {"gitleaks": "why"}}))
    assert whats(findings) == [("estate", own)]
    assert all(c["exempted"] == {} for c in classes.values())


MALFORMED = "`hook_exempt` is not a mapping of repository to {hook id: reason}; no exemption applied"


@pytest.mark.parametrize("value", [
    [],
    "seeder",
    None,
    {"seeder": ["boot-reads-watched"]},
    {"seeder": {"boot-reads-watched": 1}},
    {"seeder": {"": "why"}},
    {"seeder": {"boot\nreads": "why"}},
    {"seeder": {"boot\u200breads-watched": "why"}},
    {"seeder": {"boot-reads-watched\u2028": "why"}},
    {"seeder": {"\u202eboot-reads-watched": "why"}},
    {"seeder": {"boot-reads-watched": "why"}, "gateway": "why"},
])
def test_a_malformed_value_is_one_finding_and_applies_nothing(value):
    findings, classes = audit.hook_conformance(with_exempt(six(), value))
    assert whats(findings) == [("(estate)", MALFORMED), MISSING]
    assert all(c["exempted"] == {} for c in classes.values())
    assert audit.report(with_exempt(six(), value))[1] == 1


# --------------------------------------------------------------------------
# AC1 — gather copies the key, and reads nothing more
# --------------------------------------------------------------------------


def test_gather_copies_an_absent_hook_exempt_as_empty():
    world = gather_world()
    assert audit.gather("o", lambda path, raw=False: world[path])["classes"]["hook_exempt"] == {}


@pytest.mark.parametrize("value", [{"a": {"g": "why"}}, ["not", "a", "mapping"]])
def test_gather_copies_hook_exempt_verbatim_with_no_extra_read(value):
    world = gather_world()
    world["repos/o/actions/contents/classes.json"] = json.dumps(
        {"exempt": {}, "sweep": {"exclude": {}}, "hook_exempt": value})
    calls = []

    def get(path, raw=False):
        calls.append(path)
        return world[path]

    snap = audit.gather("o", get)
    assert snap["classes"]["hook_exempt"] == value
    assert len(calls) == len(world)
