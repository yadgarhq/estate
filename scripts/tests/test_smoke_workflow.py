"""`smoke.yaml`'s shape: which event reaches the rows, and where the token can go.

The `if:` conditions are EVALUATED, not string-matched: a small evaluator for
the subset of GitHub's expression language these conditions use (`always()`,
`==`, `!=`, `&&`, `||`, parentheses, string literals, dotted contexts) runs
each condition against each event. Anything outside that subset is a parse
error, so a condition rewritten into syntax the evaluator cannot read fails
here rather than passing unread.
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
SMOKE = yaml.safe_load((WORKFLOWS / "smoke.yaml").read_text())
# PyYAML reads the key `on` as the boolean True (YAML 1.1); the trap is real.
TRIGGERS = SMOKE.get("on", SMOKE.get(True))
JOBS = SMOKE["jobs"]
TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||==|!=|!|'[^']*'|always\(\)|cancelled\(\)|[A-Za-z_][\w.\-]*)")


def evaluate(expr: str, ctx: dict) -> bool:
    expr = expr.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    tokens, pos = [], 0
    while pos < len(expr.rstrip()):
        m = TOKEN.match(expr, pos)
        if not m:
            raise SyntaxError(f"unreadable condition at {expr[pos:]!r}")
        tok = m.group(1)
        if re.fullmatch(r"[A-Za-z_][\w.\-]*", tok) and expr[m.end():].lstrip().startswith("("):
            raise SyntaxError(f"function {tok}() is outside the subset this evaluator reads")
        tokens.append(tok)
        pos = m.end()
    i = 0

    def atom():
        nonlocal i
        tok = tokens[i]
        i += 1
        if tok == "(":
            v = disj()
            assert tokens[i] == ")"
            i += 1
            return v
        if tok == "!":
            return not atom()
        if tok == "always()":
            return True
        if tok == "cancelled()":
            return ctx.get("cancelled()", False)
        if tok.startswith("'"):
            return tok[1:-1]
        return ctx.get(tok, "")

    def comparison():
        nonlocal i
        left = atom()
        if i < len(tokens) and tokens[i] in ("==", "!="):
            op = tokens[i]
            i += 1
            right = atom()
            return (left == right) if op == "==" else (left != right)
        return left

    def conj():
        nonlocal i
        v = comparison()
        while i < len(tokens) and tokens[i] == "&&":
            i += 1
            v = comparison() and v
        return bool(v)

    def disj():
        nonlocal i
        v = conj()
        while i < len(tokens) and tokens[i] == "||":
            i += 1
            v = conj() or v
        return bool(v)

    out = disj()
    assert i == len(tokens), f"trailing tokens in {expr!r}"
    return out


def reaches_smoke(event: str, verdict_result: str = "success", run: str = "true", jobs: dict = JOBS) -> bool:
    ctx = {"github.event_name": event}
    # No `if:` is GitHub's default, which runs the job.
    verdict_runs = evaluate(jobs["verdict"].get("if", "always()"), ctx)
    ctx["needs.verdict.result"] = verdict_result if verdict_runs else "skipped"
    ctx["needs.verdict.outputs.run"] = run if verdict_runs else ""
    smoke_if = jobs["smoke"]["if"]
    # GitHub's implicit `success()`: without a status function in `if:`, a need
    # that did not succeed skips the job before the expression is read.
    if "always()" not in smoke_if and "cancelled()" not in smoke_if and ctx["needs.verdict.result"] != "success":
        return False
    return evaluate(smoke_if, ctx)


def triggers_of(workflow: dict) -> dict:
    return workflow.get("on", workflow.get(True))


def only_the_poll_and_a_hand_run(workflow: dict) -> bool:
    return set(triggers_of(workflow)) == {"schedule", "workflow_dispatch"}


def test_exactly_two_triggers():
    assert only_the_poll_and_a_hand_run(SMOKE)
    assert TRIGGERS["schedule"] == [{"cron": "*/15 * * * *"}]


def test_mutation_restoring_module_rolled_reddens_the_trigger_check():
    """Ledger 675 stage 7 retired `repository_dispatch` (`module-rolled`). The
    check above must go red if it comes back."""
    mutated = copy.deepcopy(SMOKE)
    triggers_of(mutated)["repository_dispatch"] = {"types": ["module-rolled"]}
    assert not only_the_poll_and_a_hand_run(mutated)


def test_every_event_needs_a_green_verdict():
    """No event reaches the rows past the `verdict` job any more. Before stage
    7, `repository_dispatch` skipped `verdict` and still reached `smoke`."""
    assert "if" not in JOBS["verdict"]
    for event in ("schedule", "workflow_dispatch", "repository_dispatch"):
        assert not reaches_smoke(event, "success", "false")
        assert not reaches_smoke(event, "failure", "")


def test_mutation_the_old_dispatch_bypass_reaches_smoke_without_a_verdict():
    """Proves the test above can fail: restore the pre-stage-7 conditions and
    `repository_dispatch` reaches the rows with `verdict` skipped."""
    jobs = copy.deepcopy(JOBS)
    jobs["verdict"]["if"] = "github.event_name != 'repository_dispatch'"
    jobs["smoke"]["if"] = (
        "always() && ((github.event_name == 'repository_dispatch') || "
        "(needs.verdict.result == 'success' && needs.verdict.outputs.run == 'true'))"
    )
    assert reaches_smoke("repository_dispatch", "success", "false", jobs)


@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch"])
def test_the_poll_and_a_hand_run_reach_smoke_only_on_a_decided_run(event):
    assert reaches_smoke(event, "success", "true")
    assert not reaches_smoke(event, "success", "false")
    assert not reaches_smoke(event, "failure", "true")
    assert not reaches_smoke(event, "failure", "")
    assert not reaches_smoke(event, "cancelled", "")


def test_no_step_waits_on_a_roll():
    """Ledger 675 stage 7 deleted `await-roll`; nothing here reads a dispatch payload."""
    text = (WORKFLOWS / "smoke.yaml").read_text()
    for step in JOBS["smoke"]["steps"]:
        assert "await-roll" not in step.get("run", "")
        assert "ESTATE_ROLLED_" not in str(step.get("env", {}))
    assert "client_payload" not in text


def test_the_certificate_is_uploaded_on_every_verdict_driven_run_pass_or_fail():
    upload = next(s for s in JOBS["smoke"]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    write = next(s for s in JOBS["smoke"]["steps"] if s.get("name") == "write the certificate")
    assert upload["with"]["name"] == "smoke-certified-${{ needs.verdict.outputs.epoch }}"
    ok = {"needs.verdict.outputs.inventory": "ok"}
    for step in (write, upload):
        assert evaluate(step["if"], {"github.event_name": "schedule", **ok})
        assert evaluate(step["if"], {"github.event_name": "workflow_dispatch", **ok})
        # a cancelled run certified nothing and must not block the next poll
        assert not evaluate(step["if"], {"github.event_name": "schedule", "cancelled()": True, **ok})


# yaadgaar #549, ruled 2026-11-03 (option b): inventory drift reds the C-18 rows
# only. These read the workflow's STRUCTURE (conditions, env, the step's own
# shell); no test here runs GitHub Actions.


@pytest.mark.parametrize("inventory", ["drift", "", "unknown"])
def test_no_certificate_while_the_inventory_is_not_ok(inventory):
    """A drift run certifies nothing, so the next poll asks again and C-18 stays
    red every poll until the re-pin, as the whole-job red did before."""
    for step in JOBS["smoke"]["steps"]:
        if step.get("name") == "write the certificate" or step.get("uses", "").startswith("actions/upload-artifact@"):
            assert not evaluate(step["if"], {"github.event_name": "schedule",
                                             "needs.verdict.outputs.inventory": inventory})


def test_the_verdict_job_hands_the_inventory_state_on():
    assert JOBS["verdict"]["outputs"]["inventory"] == "${{ steps.decide.outputs.inventory }}"


def c18_step():
    return next(s for s in JOBS["smoke"]["steps"] if s.get("id") == "confinement")


def run_c18(tmp_path, inventory):
    """Run the C-18 step's own shell with a fake `cargo` that records its call."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "cargo.log"
    cargo = bin_dir / "cargo"
    cargo.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
    cargo.chmod(0o755)
    # Only the fake on PATH: the step's shell needs nothing but builtins and `cargo`.
    env = {"PATH": str(bin_dir), "INVENTORY": inventory}
    assert c18_step()["env"]["INVENTORY"] == "${{ needs.verdict.outputs.inventory }}"
    bash = shutil.which("bash")
    assert bash, "the test needs bash, as the runner's `run:` shell is"
    done = subprocess.run([bash, "-c", c18_step()["run"]], env=env, capture_output=True, text=True)
    return done.returncode, log.read_text() if log.exists() else "", done.stdout


def test_the_c18_step_runs_the_confinement_rows_on_a_clean_inventory(tmp_path):
    code, cargo, _ = run_c18(tmp_path, "ok")
    assert code == 0
    assert cargo.strip() == "test --locked --test confinement -- --ignored --nocapture"


@pytest.mark.parametrize("inventory", ["drift", "", "OK"])
def test_the_c18_step_is_red_on_anything_but_a_clean_inventory(tmp_path, inventory):
    code, cargo, out = run_c18(tmp_path, inventory)
    assert code == 1 and cargo == ""
    assert "::error" in out and "C-18 inventory" in out


def summary_step():
    return next(s for s in JOBS["smoke"]["steps"] if s.get("name") == "say what C-18 answered, on the run")


def run_summary(tmp_path, outcome, inventory):
    """Run the C-18 summary step's own shell and return what it wrote to the run summary."""
    out = tmp_path / "summary.md"
    step = summary_step()
    assert step["env"]["INVENTORY"] == "${{ needs.verdict.outputs.inventory }}"
    assert step["env"]["OUTCOME"] == "${{ steps.confinement.outcome }}"
    bash = shutil.which("bash")
    assert bash, "the test needs bash, as the runner's `run:` shell is"
    env = {"PATH": "", "OUTCOME": outcome, "INVENTORY": inventory, "GITHUB_STEP_SUMMARY": str(out)}
    done = subprocess.run([bash, "-c", step["run"]], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    return out.read_text()


@pytest.mark.parametrize("outcome", ["skipped", "cancelled"])
@pytest.mark.parametrize("inventory", ["drift", "", "unknown"])
def test_a_c18_that_did_not_run_still_names_the_drift(tmp_path, outcome, inventory):
    """Drift plus a front-door failure skips the C-18 step, so its own drift error
    never prints. The summary must say the inventory was not `ok` (yaadgaar #559
    item 5); anything but `ok` counts, as the step's own gate does."""
    text = run_summary(tmp_path, outcome, inventory)
    assert "C-18 did NOT run" in text
    assert "INVENTORY DRIFT" in text and "reference.toml" in text


@pytest.mark.parametrize("outcome", ["skipped", "cancelled"])
def test_a_c18_that_did_not_run_on_a_clean_inventory_names_no_drift(tmp_path, outcome):
    text = run_summary(tmp_path, outcome, "ok")
    assert "C-18 did NOT run" in text
    assert "DRIFT" not in text.upper()


def test_a_c18_red_on_drift_keeps_its_own_drift_text(tmp_path):
    text = run_summary(tmp_path, "failure", "drift")
    assert "RED ON INVENTORY DRIFT" in text


def test_drift_does_not_stop_the_front_door_rows():
    front = next(s for s in JOBS["smoke"]["steps"] if s.get("name") == "the front-door contracts")
    assert "if" not in front and "inventory" not in str(front)


def test_the_verdict_job_is_confined():
    job = JOBS["verdict"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["environment"] == "verdict-reader"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert set(job["outputs"]) == {"run", "epoch", "verdict_url", "inventory"}
    assert "secrets" not in str(job["outputs"])
    decide = next(s for s in job["steps"] if s.get("id") == "decide")
    assert decide["run"] == "python3 scripts/verdict.py"
    assert decide["env"]["VERDICT_TOKEN"] == "${{ secrets.ARGOCD_VERIFY_READ_TOKEN }}"
    for step in job["steps"]:
        if step is not decide:
            assert "secrets." not in str(step), f"the token reaches {step}"
        if step.get("uses", "").startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False
            assert set(step["with"]) == {"persist-credentials"}, "the verdict job checks out no other ref or repo"


def test_the_token_and_the_environment_are_named_exactly_once():
    text = "".join(p.read_text() for p in sorted(WORKFLOWS.glob("*.y*ml")))
    assert text.count("secrets.ARGOCD_VERIFY_READ_TOKEN") == 1
    assert len(re.findall(r"environment:\s*verdict-reader", text)) == 1


def test_no_workflow_runs_in_mains_context_with_pr_input():
    for path in WORKFLOWS.glob("*.y*ml"):
        doc = yaml.safe_load(path.read_text())
        on = doc.get("on", doc.get(True))
        names = set(on) if isinstance(on, (dict, list)) else {on}
        assert not names & {"pull_request_target", "workflow_run"}, path.name


def test_every_action_is_pinned_by_full_sha():
    for job in JOBS.values():
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[\w.\-]+/[\w.\-]+@[0-9a-f]{40}", step["uses"]), step["uses"]


def test_the_dispatch_inputs_are_recertify_and_token_probe():
    inputs = TRIGGERS["workflow_dispatch"]["inputs"]
    assert set(inputs) == {"recertify", "token_probe"}
    assert inputs["recertify"]["type"] == "boolean"
    assert inputs["token_probe"]["options"] == ["real", "own-github-token", "bogus"]
    assert inputs["token_probe"]["default"] == "real"


def test_the_evaluator_refuses_syntax_it_cannot_read():
    with pytest.raises(SyntaxError):
        evaluate("contains(github.event_name, 'x')", {})
