"""The decision table of `smoke.yaml`'s `verdict` job (gate plan, stage 5).

Red (job fails, run=false): token rejected, token empty, malformed verdict, a
verdict whose anchor matches but whose key does not, estate unable to list its
own certificates. Quiet run=false: no verdict yet, a red verdict, already
certified. run=true only on a green verdict no smoke run has certified.
"""

from __future__ import annotations

import json

import pytest
from conftest import ESTATE_ID, FORK_ID, OWN_TOKEN, SHA_D41, VERIFY_TOKEN, run, verdict_zip
from test_verdict_key import K_D41C07F

import verdict

EPOCH = f"{K_D41C07F}-{SHA_D41}"


def green(**over):
    v = {"S": SHA_D41, "P": "0.3.38", "K": K_D41C07F, "A": SHA_D41, "result": "green"}
    v.update(over)
    return v


def test_a_green_verdict_nobody_certified_runs_the_rows(world):
    world.add_verdict(7, green())
    d = run(world)
    assert (d.run, d.epoch) == (True, EPOCH)
    assert d.verdict_url == "https://github.com/yadgarhq/argocd-verify/actions/runs/50007"


def test_no_verdict_for_the_epoch_is_waiting_not_red(world):
    d = run(world)
    assert not d.run
    assert d.summary.startswith("waiting for a verdict on render")


def test_a_verdict_for_an_older_epoch_is_still_waiting(world):
    world.add_verdict(7, green(K="a" * 64, A="b" * 40))
    assert run(world).summary.startswith("waiting")


def test_a_red_verdict_does_not_run_and_names_the_clause(world):
    world.add_verdict(7, green(result="red", clause="Clause A: gateway runs sha256:x, wants sha256:y"))
    d = run(world)
    assert not d.run
    assert "RED: Clause A: gateway" in d.summary


def test_the_newest_verdict_for_the_epoch_wins(world):
    world.add_verdict(7, green(result="red", clause="Clause B"))
    world.add_verdict(8, green())  # a re-judge that found it settled
    assert run(world).run


def test_an_already_certified_epoch_does_not_run_again(world):
    world.add_verdict(7, green())
    world.add_cert(EPOCH, 1)
    d = run(world)
    assert not d.run
    assert d.summary.startswith("already certified")


def test_recertify_skips_only_the_certified_check(world):
    world.add_verdict(7, green())
    world.add_cert(EPOCH, 1)
    assert run(world, recertify=True).run


def test_recertify_cannot_run_the_rows_without_a_green_verdict(world):
    world.add_verdict(7, green(result="red", clause="Clause A"))
    assert not run(world, recertify=True).run


@pytest.mark.parametrize(
    "where",
    [
        {"branch": "feature"},
        {"head_repo": FORK_ID},
        {"path": ".github/workflows/verify.yaml"},
        {"name": "settled-trial"},
        {"expired": True},
    ],
    ids=["non-default-branch", "fork", "other-workflow", "settled-trial", "expired"],
)
def test_verdicts_from_anywhere_but_settled_yaml_on_main_are_ignored(world, where):
    world.add_verdict(7, green(), **where)
    assert run(world).summary.startswith("waiting")


@pytest.mark.parametrize(
    "where",
    [{"branch": "feature"}, {"head_repo": FORK_ID}, {"path": ".github/workflows/ci.yaml"}],
    ids=["non-default-branch", "fork-planted", "other-workflow"],
)
def test_certificates_from_anywhere_but_smoke_yaml_on_main_are_ignored(world, where):
    # Estate is public: a fork run can upload `smoke-certified-<E>` and would
    # otherwise silence smoke for that epoch.
    world.add_verdict(7, green())
    world.add_cert(EPOCH, 1, **where)
    assert run(world).run


def test_same_anchor_different_key_is_red(world):
    world.add_verdict(7, green(K="c" * 64))
    with pytest.raises(verdict.Red, match="key computation disagrees"):
        run(world)


@pytest.mark.parametrize(
    "payload",
    [
        "not json",
        {"K": K_D41C07F, "A": SHA_D41, "result": "green"},  # no S, no P
        green(result="maybe"),
        green(result="red"),  # red without a clause
        green(K="NOT-HEX"),
    ],
)
def test_a_malformed_verdict_is_red_not_waiting(world, payload):
    world.add_verdict(7, green())
    world.route("https://blob.example/7.zip", verdict_zip(payload))
    with pytest.raises(verdict.Red, match="malformed|no readable"):
        run(world)


@pytest.mark.parametrize("status", [401, 403, 404])
def test_a_rejected_token_is_red_naming_the_status(world, status):
    world.statuses[f"/repos/{verdict.VERIFY}/"] = status
    with pytest.raises(verdict.Red, match=f"argocd-verify answered {status}"):
        run(world)


def test_an_empty_token_is_red_before_any_argocd_verify_call(world):
    with pytest.raises(verdict.Red, match="verdict-reader"):
        run(world, verify_token="")
    assert not [u for u, _ in world.calls if "argocd-verify" in u]


@pytest.mark.parametrize("status", [401, 403, 404])
def test_estate_unable_to_list_its_own_certificates_is_red_not_run(world, status):
    world.add_verdict(7, green())
    world.statuses["/repos/yadgarhq/estate/actions/"] = status
    with pytest.raises(verdict.Red, match=f"estate's own artifact listing answered {status}"):
        run(world)


def test_a_consistency_mismatch_is_red_before_the_token_is_used(world):
    bad = json.dumps({"chart_tag": "v0.3.37"}).encode()
    world.route(f"/repos/{verdict.ARGOCD}/contents/{verdict.PIN_PATH}?ref={SHA_D41}", bad)
    with pytest.raises(verdict.Red, match="chart_tag"):
        run(world)
    assert all(tok == OWN_TOKEN for _, tok in world.calls)


def test_each_token_goes_only_where_it_belongs(world):
    world.add_verdict(7, green())
    run(world)
    for url, tok in world.calls:
        if url.startswith("https://blob.example/"):
            assert tok is None, "the artifact redirect must not carry a token"
        elif "/repos/yadgarhq/argocd-verify/" in url:
            assert tok == VERIFY_TOKEN
        else:
            assert tok == OWN_TOKEN


@pytest.mark.parametrize(
    "probe,want",
    [("", VERIFY_TOKEN), ("real", VERIFY_TOKEN), ("own-github-token", OWN_TOKEN),
     ("bogus", verdict.BOGUS_TOKEN)],
)
def test_token_probe_substitutes_the_token_for_the_live_red_arms(probe, want):
    env = {"VERDICT_TOKEN": VERIFY_TOKEN, "GITHUB_TOKEN": OWN_TOKEN}
    assert verdict.choose_token(probe, env) == want


def test_an_unknown_token_probe_is_red():
    with pytest.raises(verdict.Red, match="token_probe"):
        verdict.choose_token("admin", {})


def test_main_writes_outputs_and_fails_closed(world, tmp_path):
    out, summary = tmp_path / "out", tmp_path / "summary"
    env = {
        "GITHUB_REPOSITORY": "yadgarhq/estate", "GITHUB_REPOSITORY_ID": str(ESTATE_ID),
        "GITHUB_TOKEN": OWN_TOKEN, "VERDICT_TOKEN": "", "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    assert verdict.main(env, world) == 1
    assert "run=false" in out.read_text()
    assert "REFUSED" in summary.read_text()
    env["VERDICT_TOKEN"] = VERIFY_TOKEN
    world.add_verdict(7, green())
    out.write_text("")
    assert verdict.main(env, world) == 0
    assert f"run=true\nepoch={EPOCH}\n" in out.read_text()
    assert VERIFY_TOKEN not in summary.read_text() + out.read_text()
