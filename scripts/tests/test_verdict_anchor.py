"""The anchor A: the epoch is (K, A), so a revert A -> B -> A is a new epoch.

The first case is real argocd history (`git log origin/main --
applications/yadgar.yaml scripts/gates/yadgar_render.sha256`, measured
2026-10-03): eb43ea9 created both files, d41c07f changed both. git names
d41c07f as the anchor at main, and so must the walk over the API's two lists.
"""

from __future__ import annotations

import pytest
from conftest import SHA_13A, SHA_D41, OWN_TOKEN, FakeGitHub, commit, fixture_files

import verdict

T, APP = verdict.TABLE_PATH, verdict.APP_PATH
OLD, NEW = fixture_files(SHA_13A), fixture_files(SHA_D41)


def anchor(gh: FakeGitHub) -> str:
    """The walk at `gh.head`, with the head's files read from the declared world."""
    head = {p: gh.routes[f"{verdict.API}/repos/{verdict.ARGOCD}/contents/{p}?ref={gh.head}"].body for p in (T, APP)}
    key = verdict.render_key(head[T], head[APP])
    return verdict.find_anchor(verdict.GitHub(gh, OWN_TOKEN, "argocd"), gh.head, head, key)[0]


def test_real_history_anchors_at_d41c07f(world):
    assert anchor(world) == SHA_D41


def test_the_public_half_costs_nine_calls_and_a_poll_twelve(world):
    """Measured, not stated: 9 public argocd calls (branch, 3 files, 2 path lists,
    1 unfiltered page for hidden merges, 2 walk reads), then 3 with the token
    (list, run, artifact). The blob hop is not an API call and carries no token."""
    from conftest import run

    world.add_verdict(1, {"S": SHA_D41, "P": "0.3.38", "K": "0" * 64, "A": "1" * 40, "result": "green"})
    run(world)
    api = [u for u, _ in world.calls if u.startswith(verdict.API)]
    public = [u for u in api if f"/repos/{verdict.ARGOCD}/" in u]
    assert (len(public), len(api)) == (9, 12), api


def _three(shas, dates, table_list, app_list, versions, head):
    gh = FakeGitHub()
    hist = {T: [commit(s, dates[s]) for s in table_list], APP: [commit(s, dates[s]) for s in app_list]}
    files = {}
    for (path, sha), blob in versions.items():
        files[(path, sha)] = blob
    gh.argocd(head, hist, files)
    return gh


DATES = {c: f"2026-10-0{i + 1}T10:00:00Z" for i, c in enumerate("abcdef")}
C = {c: c * 40 for c in "abcdef"}
D = {C[c]: DATES[c] for c in DATES}


def test_a_revert_to_an_earlier_render_is_a_new_epoch():
    # a: render OLD; b: render NEW; c: back to OLD. Head c's K equals a's, but A is c.
    order = [C["c"], C["b"], C["a"]]
    versions = {}
    for sha, f in ((C["a"], OLD), (C["b"], NEW), (C["c"], OLD)):
        versions[(T, sha)], versions[(APP, sha)] = f[T], f[APP]
    gh = _three(order, D, order, order, versions, C["c"])
    key = verdict.render_key(OLD[T], OLD[APP])
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    assert verdict.find_anchor(api, C["c"], {T: OLD[T], APP: OLD[APP]}, key)[0] == C["c"]


def test_a_comment_only_edit_does_not_move_the_anchor():
    # a: render NEW; b: same render, a comment added to the Application. A stays a.
    commented = NEW[APP].replace(b"    chart: yadgar\n", b"    chart: yadgar  # note\n", 1)
    versions = {(T, C["a"]): NEW[T], (APP, C["a"]): NEW[APP], (APP, C["b"]): commented}
    gh = _three(None, D, [C["a"]], [C["b"], C["a"]], versions, C["b"])
    key = verdict.render_key(NEW[T], commented)
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    assert verdict.find_anchor(api, C["b"], {T: NEW[T], APP: commented}, key)[0] == C["a"]


def test_when_history_runs_out_the_oldest_listed_commit_is_the_anchor():
    versions = {(T, C["a"]): NEW[T], (APP, C["a"]): NEW[APP], (APP, C["b"]): NEW[APP]}
    gh = _three(None, D, [C["a"]], [C["b"], C["a"]], versions, C["b"])
    key = verdict.render_key(NEW[T], NEW[APP])
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    assert verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, key)[0] == C["a"]


def test_a_commit_before_one_file_existed_ends_the_walk():
    # b created the table; a (older) touched only the Application. K at a is undefined.
    versions = {(APP, C["a"]): NEW[APP]}
    gh = _three(None, D, [C["b"]], [C["b"], C["a"]], versions, C["b"])
    key = verdict.render_key(NEW[T], NEW[APP])
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    assert verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, key)[0] == C["b"]


def test_a_merge_commit_is_red():
    gh = FakeGitHub()
    hist = [commit(C["b"], DATES["b"], parents=2), commit(C["a"], DATES["a"])]
    gh.argocd(C["b"], {T: hist, APP: hist}, {})
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    with pytest.raises(verdict.Red, match="two parents"):
        verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, "k")


def test_two_commits_at_one_instant_are_red():
    gh = FakeGitHub()
    gh.argocd(C["b"], {T: [commit(C["b"], DATES["b"])], APP: [commit(C["a"], DATES["b"])]}, {})
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    with pytest.raises(verdict.Red, match="share a committer date"):
        verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, "k")


def test_an_api_order_that_contradicts_the_dates_is_red():
    gh = FakeGitHub()
    hist = [commit(C["a"], DATES["a"]), commit(C["b"], DATES["b"])]
    gh.argocd(C["b"], {T: hist, APP: hist}, {})
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    with pytest.raises(verdict.Red, match="contradicts committer dates"):
        verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, "k")


def test_an_unbounded_walk_refuses_rather_than_guesses():
    # Ten comment-only edits in a row: the walk would need more reads than allowed.
    shas = [chr(ord("a") + i) * 40 for i in range(12)]
    dates = {s: f"2026-09-{10 + i:02d}T10:00:00Z" for i, s in enumerate(reversed(shas))}
    versions = {(T, shas[-1]): NEW[T]}
    for i, s in enumerate(shas):
        versions[(APP, s)] = NEW[APP] + f"# edit {i}\n".encode()
    gh = _three(None, dates, [shas[-1]], shas, versions, shas[0])
    head_app = versions[(APP, shas[0])]
    key = verdict.render_key(NEW[T], head_app)
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    with pytest.raises(verdict.Red, match="more than"):
        verdict.find_anchor(api, shas[0], {T: NEW[T], APP: head_app}, key)


def test_the_anchor_comes_back_with_its_committer_date(world):
    head = {p: world.routes[f"{verdict.API}/repos/{verdict.ARGOCD}/contents/{p}?ref={SHA_D41}"].body for p in (T, APP)}
    key = verdict.render_key(head[T], head[APP])
    sha, date, _ = verdict.find_anchor(verdict.GitHub(world, OWN_TOKEN, "argocd"), SHA_D41, head, key)
    assert (sha, date.isoformat()) == (SHA_D41, "2026-10-02T22:31:27+00:00")


def test_a_full_page_of_history_is_red_not_the_oldest_listed():
    shas = [f"{i:040x}" for i in range(100)]
    hist = [commit(s, f"2026-01-01T00:00:{i % 60:02d}Z") for i, s in enumerate(shas)]
    gh = FakeGitHub()
    gh.argocd(shas[0], {T: hist, APP: hist[:1]}, {})
    api = verdict.GitHub(gh, OWN_TOKEN, "argocd")
    with pytest.raises(verdict.Red, match="a full page"):
        verdict.find_anchor(api, shas[0], {T: NEW[T], APP: NEW[APP]}, "k")


def _with_mainline(mainline):
    hist = [commit(C["b"], DATES["b"]), commit(C["a"], DATES["a"])]
    gh = FakeGitHub()
    versions = {(T, C["a"]): NEW[T], (APP, C["a"]): NEW[APP]}
    gh.argocd(C["b"], {T: hist[1:], APP: hist}, versions, mainline=mainline)
    return verdict.GitHub(gh, OWN_TOKEN, "argocd")


def test_a_merge_commit_the_path_filter_hid_is_red():
    # Hello-World 7fd1a60's shape: the merge is TREESAME to a parent, so neither
    # path list shows it; only the unfiltered page does.
    hidden = commit("f" * 40, "2026-10-01T12:00:00Z", parents=2)
    api = _with_mainline([commit(C["b"], DATES["b"]), hidden, commit(C["a"], DATES["a"])])
    with pytest.raises(verdict.Red, match=f"merge commit {'f' * 40}"):
        verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, verdict.render_key(NEW[T], NEW[APP]))


def test_a_merge_older_than_the_walk_is_not_its_business():
    old_merge = commit("f" * 40, "2026-09-01T12:00:00Z", parents=2)
    api = _with_mainline([commit(C["b"], DATES["b"]), commit(C["a"], DATES["a"]), old_merge])
    assert verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, verdict.render_key(NEW[T], NEW[APP]))[0] == C["a"]


def test_an_oldest_walked_commit_beyond_the_unfiltered_page_is_red():
    api = _with_mainline([commit(C["b"], DATES["b"])])
    with pytest.raises(verdict.Red, match="cannot rule out a merge commit"):
        verdict.find_anchor(api, C["b"], {T: NEW[T], APP: NEW[APP]}, verdict.render_key(NEW[T], NEW[APP]))
