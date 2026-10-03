"""`smoke.yaml`'s shape: which event reaches the rows, and where the token can go.

The `if:` conditions are EVALUATED, not string-matched: a small evaluator for
the subset of GitHub's expression language these conditions use (`always()`,
`==`, `!=`, `&&`, `||`, parentheses, string literals, dotted contexts) runs
each condition against each event. Anything outside that subset is a parse
error, so a condition rewritten into syntax the evaluator cannot read fails
here rather than passing unread.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
SMOKE = yaml.safe_load((WORKFLOWS / "smoke.yaml").read_text())
# PyYAML reads the key `on` as the boolean True (YAML 1.1); the trap is real.
TRIGGERS = SMOKE.get("on", SMOKE.get(True))
JOBS = SMOKE["jobs"]
TOKEN = re.compile(r"\s*(\(|\)|&&|\|\||==|!=|'[^']*'|always\(\)|[A-Za-z_][\w.\-]*)")


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
        if tok == "always()":
            return True
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


def reaches_smoke(event: str, verdict_result: str = "success", run: str = "true") -> bool:
    ctx = {"github.event_name": event}
    verdict_runs = evaluate(JOBS["verdict"]["if"], ctx)
    ctx["needs.verdict.result"] = verdict_result if verdict_runs else "skipped"
    ctx["needs.verdict.outputs.run"] = run if verdict_runs else ""
    return evaluate(JOBS["smoke"]["if"], ctx)


def test_exactly_three_triggers():
    assert set(TRIGGERS) == {"repository_dispatch", "schedule", "workflow_dispatch"}
    assert TRIGGERS["repository_dispatch"]["types"] == ["module-rolled"]
    assert TRIGGERS["schedule"] == [{"cron": "*/15 * * * *"}]


def test_repository_dispatch_reaches_smoke_without_the_verdict_job():
    assert not evaluate(JOBS["verdict"]["if"], {"github.event_name": "repository_dispatch"})
    assert reaches_smoke("repository_dispatch")


@pytest.mark.parametrize("event", ["schedule", "workflow_dispatch"])
def test_the_poll_and_a_hand_run_reach_smoke_only_on_a_decided_run(event):
    assert reaches_smoke(event, "success", "true")
    assert not reaches_smoke(event, "success", "false")
    assert not reaches_smoke(event, "failure", "true")
    assert not reaches_smoke(event, "failure", "")
    assert not reaches_smoke(event, "cancelled", "")


def test_await_roll_runs_on_repository_dispatch_only():
    step = next(s for s in JOBS["smoke"]["steps"] if s.get("run", "").endswith("--bin await-roll"))
    for event, want in (("repository_dispatch", True), ("schedule", False), ("workflow_dispatch", False)):
        assert evaluate(step["if"], {"github.event_name": event}) is want
    assert "inputs." not in str(step["env"])


def test_the_certificate_is_uploaded_on_every_verdict_driven_run_pass_or_fail():
    upload = next(s for s in JOBS["smoke"]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "smoke-certified-${{ needs.verdict.outputs.epoch }}"
    assert upload["if"].startswith("always()")
    assert evaluate(upload["if"], {"github.event_name": "schedule"})
    assert not evaluate(upload["if"], {"github.event_name": "repository_dispatch"})


def test_the_verdict_job_is_confined():
    job = JOBS["verdict"]
    assert job["runs-on"] == "ubuntu-latest"
    assert job["environment"] == "verdict-reader"
    assert job["permissions"] == {"contents": "read", "actions": "read"}
    assert set(job["outputs"]) == {"run", "epoch", "verdict_url"}
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
