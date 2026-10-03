"""Shared fixtures for `scripts/tests/`: the subject on the path, and a fake GitHub.

The fake answers only the URLs a test declares. An undeclared URL raises rather
than answering 404, because a 404 is itself a case under test (the token arm)
and a fake that invents one would let a wrong URL pass as a refusal.

THE FIELD NAMES ARE GITHUB'S, measured 2026-10-03 on a real pair from
`yadgarhq/actions` (artifact 11256977198, run 37076269754): an artifact's
`workflow_run` carries `id`, `repository_id`, `head_repository_id` and
`head_branch`; a run carries `path` as `.github/workflows/<file>.yaml`,
`head_branch` and `head_repository.id`. A wrong name here would filter out
every real verdict and leave smoke "waiting" forever, green and silent.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.parse
import zipfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

import verdict  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "argocd"
SHA_13A = "13a2db639209016b7e77d98c9a84c8529c11b5ae"
SHA_D41 = "d41c07f8c7b870d45b8925c3c0dc57e29af492b1"
SHA_EB4 = "eb43ea90f2b037cab8b9fc4f9dd6f4f641a952be"
VERIFY_ID = 1001
ESTATE_ID = 2002
FORK_ID = 3003
VERIFY_TOKEN = "verify-token-under-test"
OWN_TOKEN = "own-token-under-test"


def fixture_files(sha: str) -> dict[str, bytes]:
    d = FIXTURES / sha
    return {
        verdict.TABLE_PATH: (d / "yadgar_render.sha256").read_bytes(),
        verdict.APP_PATH: (d / "yadgar.yaml").read_bytes(),
        verdict.PIN_PATH: (d / "chart_pin.json").read_bytes(),
    }


def verdict_zip(payload) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(verdict.VERDICT_FILE, payload if isinstance(payload, str) else json.dumps(payload))
    return buf.getvalue()


def commit(sha: str, date: str, parents: int = 1) -> dict:
    return {"sha": sha, "parents": [{"sha": "p"}] * parents, "commit": {"committer": {"date": date}}}


class FakeGitHub:
    """A declared world: argocd history and files, argocd-verify, estate."""

    def __init__(self):
        self.routes: dict[str, verdict.Response] = {}
        self.calls: list[tuple[str, str | None]] = []
        self.head = SHA_D41
        self.verify_artifacts: list[dict] = []
        self.estate_artifacts: dict[str, list[dict]] = {}
        self.statuses: dict[str, int] = {}

    # declaring the world
    def route(self, path: str, body, status: int = 200, location: str | None = None):
        url = path if path.startswith("https://") else verdict.API + path
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.routes[url] = verdict.Response(status, raw, location)

    def argocd(self, head: str, history: dict[str, list[dict]], files: dict[tuple[str, str], bytes]):
        self.head = head
        self.route(f"/repos/{verdict.ARGOCD}/branches/main", {"commit": {"sha": head}})
        for path, items in history.items():
            q = urllib.parse.urlencode({"sha": head, "path": path, "per_page": 100})
            self.route(f"/repos/{verdict.ARGOCD}/commits?{q}", items)
        for (path, ref), data in files.items():
            self.route(f"/repos/{verdict.ARGOCD}/contents/{path}?ref={ref}", data)

    def real_argocd(self):
        """argocd main as measured: eb43ea9 created both files, d41c07f changed both."""
        history = [commit(SHA_D41, "2026-10-02T22:31:27Z"), commit(SHA_EB4, "2026-10-01T17:15:57Z")]
        d41, old = fixture_files(SHA_D41), fixture_files(SHA_13A)
        files = {(p, SHA_D41): d41[p] for p in d41}
        files.update({(p, SHA_EB4): old[p] for p in old})
        self.argocd(SHA_D41, {verdict.TABLE_PATH: history, verdict.APP_PATH: history}, files)

    def add_verdict(self, art_id: int, payload, *, name=verdict.VERDICT_ARTIFACT, branch="main",
                    head_repo=VERIFY_ID, path=verdict.VERDICT_WORKFLOW, expired=False):
        run_id = 50000 + art_id
        self.verify_artifacts.append({
            "id": art_id, "name": name, "expired": expired,
            "workflow_run": {"id": run_id, "repository_id": VERIFY_ID,
                             "head_repository_id": head_repo, "head_branch": branch},
        })
        self.route(f"/repos/{verdict.VERIFY}/actions/runs/{run_id}",
                   {"path": path, "head_branch": branch, "head_repository": {"id": head_repo}})
        blob = f"https://blob.example/{art_id}.zip"
        self.route(f"/repos/{verdict.VERIFY}/actions/artifacts/{art_id}/zip", b"", 302, blob)
        self.route(blob, verdict_zip(payload))

    def add_cert(self, epoch: str, art_id: int, *, branch="main", head_repo=ESTATE_ID,
                 path=verdict.SMOKE_WORKFLOW):
        run_id = 70000 + art_id
        self.estate_artifacts.setdefault(epoch, []).append({
            "id": art_id, "name": verdict.CERT_PREFIX + epoch, "expired": False,
            "workflow_run": {"id": run_id, "repository_id": ESTATE_ID,
                             "head_repository_id": head_repo, "head_branch": branch},
        })
        self.route(f"/repos/yadgarhq/estate/actions/runs/{run_id}",
                   {"path": path, "head_branch": branch, "head_repository": {"id": head_repo}})

    def __call__(self, url: str, token):
        self.calls.append((url, token))
        for prefix, status in self.statuses.items():
            if url.startswith(verdict.API + prefix):
                return verdict.Response(status, b'{"message":"no"}')
        listing = f"{verdict.API}/repos/{verdict.VERIFY}/actions/artifacts?"
        if url.startswith(listing):
            return verdict.Response(200, json.dumps({"artifacts": self.verify_artifacts}).encode())
        est = f"{verdict.API}/repos/yadgarhq/estate/actions/artifacts?"
        if url.startswith(est):
            name = urllib.parse.parse_qs(url[len(est):])["name"][0]
            epoch = name[len(verdict.CERT_PREFIX):]
            return verdict.Response(200, json.dumps({"artifacts": self.estate_artifacts.get(epoch, [])}).encode())
        if url not in self.routes:
            raise AssertionError(f"the fake was asked for an undeclared URL: {url}")
        return self.routes[url]


def run(gh: FakeGitHub, *, verify_token=VERIFY_TOKEN, recertify=False) -> verdict.Decision:
    return verdict.decide(
        verdict.GitHub(gh, OWN_TOKEN, "argocd (public)"),
        verdict.GitHub(gh, verify_token, "argocd-verify"),
        verdict.GitHub(gh, OWN_TOKEN, "estate's own artifact listing"),
        verdict.Inputs("yadgarhq/estate", ESTATE_ID, "main", recertify),
    )


@pytest.fixture
def world() -> FakeGitHub:
    gh = FakeGitHub()
    gh.real_argocd()
    return gh
