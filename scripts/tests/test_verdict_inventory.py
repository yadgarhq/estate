"""C-18's inventory against the render argocd main commits (yaadgaar #538).

`reference.toml [confinement] inventory` was a literal: a chart that added a
Service, or moved a port, left it green. `verdict.check_inventory` compares it
with `scripts/gates/yadgar_render.sha256` at argocd main, which argocd's own
gate holds equal to `helm template` at the pin. Names are derived both ways;
ports are guarded by pinning each Service's and each MariaDB CR's digest.
Every case here is one direction of one comparison.
"""

from __future__ import annotations

import json

import pytest
import yaml

from conftest import ESTATE_ID, FIXTURES, OWN_TOKEN, SHA_D41, VERIFY_TOKEN, d41_reference, run
from test_verdict_key import K_D41C07F

import verdict

# argocd main when the pin was last copied: pin 0.50.0, the table and the
# Application fetched 2026-11-03. The decision-table world stays at d41c07f,
# where the frozen key vectors live; `conftest.run` hands it d41c07f's lines.
SHA_A73 = "a734235ba0d551f4a9bd41bf89acd17997cbd3b7"
A73 = FIXTURES / SHA_A73
TABLE = (A73 / "yadgar_render.sha256").read_bytes()
APP = (A73 / "yadgar.yaml").read_bytes()
REFERENCE = verdict.REFERENCE_PATH.read_bytes()
REAL = verdict.tomllib.loads(REFERENCE.decode())["confinement"]
HOST = ".yadgar.svc.cluster.local"


def ref(inventory=None, rendered=None) -> bytes:
    """A `[confinement]` with the real values unless a test overrides one."""
    inventory = REAL["inventory"] if inventory is None else inventory
    rendered = REAL["rendered"] if rendered is None else rendered
    return f"[confinement]\ninventory = {json.dumps(inventory)}\nrendered = {json.dumps(rendered)}\n".encode()


def table_with(add: tuple[str, ...] = (), drop: tuple[str, ...] = (), swap: dict[str, str] | None = None) -> bytes:
    lines = []
    for line in TABLE.decode().splitlines():
        key = line.partition("  ")[2]
        if key in drop:
            continue
        if swap and key in swap:
            line = f"{swap[key]}  {key}"
        lines.append(line)
    lines += [f"{'0' * 64}  {key}" for key in add]
    return ("\n".join(lines) + "\n").encode()


def check(table=TABLE, app=APP, reference=REFERENCE):
    verdict.check_inventory(table, app, reference)


def test_the_committed_reference_agrees_with_argocd_main_as_last_pinned():
    check()


def test_the_pin_holds_every_service_and_mariadb_line_of_the_render():
    lines = [ln for ln in TABLE.decode().splitlines() if "/Service//" in ln or "/MariaDB//" in ln]
    assert sorted(REAL["rendered"]) == sorted(lines)


# ── the render side: a Service or CR argocd main renders, or stops rendering ──


def test_an_extra_rendered_service_is_red():
    with pytest.raises(verdict.Red) as err:
        check(table=table_with(add=("/Service//search",)))
    assert "`/Service//search` renders at argocd main but is not pinned" in str(err.value)
    assert f"`search{HOST}`" in str(err.value)


def test_a_removed_rendered_service_is_red():
    with pytest.raises(verdict.Red) as err:
        check(table=table_with(drop=("/Service//valkey",)))
    assert "`/Service//valkey` is pinned in reference.toml but argocd main no longer renders it" in str(err.value)
    assert f"`valkey{HOST}` but argocd main renders no such Service" in str(err.value)


def test_a_changed_service_digest_is_red_because_its_ports_may_have_moved():
    with pytest.raises(verdict.Red, match=r"`/Service//valkey` changed at argocd main"):
        check(table=table_with(swap={"/Service//valkey": "f" * 64}))


def test_an_extra_mariadb_cr_is_red_and_names_both_operator_services():
    with pytest.raises(verdict.Red) as err:
        check(table=table_with(add=("k8s.mariadb.com/MariaDB//audit-db-mariadb",)))
    msg = str(err.value)
    assert f"`audit-db-mariadb{HOST}`" in msg
    assert f"`audit-db-mariadb-internal{HOST}`" in msg


def test_a_removed_mariadb_cr_is_red():
    with pytest.raises(verdict.Red) as err:
        check(table=table_with(drop=("k8s.mariadb.com/MariaDB//task-db-mariadb",)))
    assert f"`task-db-mariadb-internal{HOST}` but argocd main renders no such Service" in str(err.value)


def test_a_changed_mariadb_cr_digest_is_red():
    with pytest.raises(verdict.Red, match=r"`k8s.mariadb.com/MariaDB//iam-db-mariadb` changed"):
        check(table=table_with(swap={"k8s.mariadb.com/MariaDB//iam-db-mariadb": "f" * 64}))


def test_a_service_rendered_into_another_namespace_is_red():
    with pytest.raises(verdict.Red, match=r"`gateway\.other\.svc\.cluster\.local`"):
        check(
            table=table_with(add=("/Service/other/gateway",)),
            reference=ref(rendered=REAL["rendered"] + [f"{'0' * 64}  /Service/other/gateway"]),
        )


def test_an_unrelated_object_does_not_touch_the_inventory():
    check(table=table_with(add=("/ConfigMap//search",)))


def test_a_rendered_object_listed_twice_is_red():
    line = next(ln for ln in TABLE.decode().splitlines() if ln.endswith("/Service//valkey"))
    with pytest.raises(verdict.Red, match="listed twice"):
        check(table=TABLE + (line + "\n").encode())


# ── the reference side: what estate declares ──────────────────────────────


def test_an_extra_inventory_entry_is_red():
    with pytest.raises(verdict.Red, match=rf"inventory names `search{HOST}` but argocd main renders no such Service"):
        check(reference=ref(inventory=REAL["inventory"] + [f"search{HOST}:9000"]))


def test_a_missing_inventory_entry_is_red():
    without = [e for e in REAL["inventory"] if not e.startswith("gateway.")]
    with pytest.raises(verdict.Red, match=rf"renders Service `gateway{HOST}` but the inventory has no entry"):
        check(reference=ref(inventory=without))


def test_a_pinned_line_argocd_no_longer_has_is_red():
    with pytest.raises(verdict.Red, match=r"`/Service//search` is pinned in reference.toml but argocd main"):
        check(reference=ref(rendered=REAL["rendered"] + [f"{'0' * 64}  /Service//search"]))


def test_a_pinned_line_missing_from_the_reference_is_red():
    rest = [ln for ln in REAL["rendered"] if not ln.endswith("/Service//nats")]
    with pytest.raises(verdict.Red, match=r"`/Service//nats` renders at argocd main but is not pinned"):
        check(reference=ref(rendered=rest))


def test_a_pinned_line_listed_twice_is_red():
    with pytest.raises(verdict.Red, match="listed twice"):
        check(reference=ref(rendered=REAL["rendered"] + REAL["rendered"][:1]))


@pytest.mark.parametrize("field", ["inventory", "rendered"])
def test_an_empty_or_absent_list_is_red(field):
    want = rf"\[confinement\] {field} is absent, empty or not a list"
    with pytest.raises(verdict.Red, match=want):
        check(reference=ref(**{field: []}))
    with pytest.raises(verdict.Red, match=want):
        other = "rendered" if field == "inventory" else "inventory"
        check(reference=f"[confinement]\n{other} = {json.dumps(REAL[other])}\n".encode())


def test_a_line_whose_digest_is_not_a_sha256_is_red_even_when_both_sides_agree():
    bad = "not-a-digest"
    pinned = [ln if not ln.endswith("/Service//valkey") else f"{bad}  /Service//valkey" for ln in REAL["rendered"]]
    with pytest.raises(verdict.Red, match=r"is not `<sha256>  <object>`"):
        check(table=table_with(swap={"/Service//valkey": bad}), reference=ref(rendered=pinned))


def test_an_inventory_entry_without_a_port_is_red():
    with pytest.raises(verdict.Red, match=r"`gateway\.yadgar\.svc\.cluster\.local` is not `host:port`"):
        check(reference=ref(inventory=REAL["inventory"] + [f"gateway{HOST}"]))


def test_a_reference_that_does_not_parse_is_red():
    with pytest.raises(verdict.Red, match="reference.toml does not parse"):
        check(reference=b"[confinement\n")


def test_an_application_without_a_destination_namespace_is_red():
    app = APP.replace(b"\n    namespace: yadgar\n", b"\n")
    assert app != APP
    with pytest.raises(verdict.Red, match="spec.destination.namespace"):
        check(app=app)


# ── the operator-derived Services a hand pin cannot see (yaadgaar #549) ────
#
# `OPERATOR_SERVICES` counts a MariaDB CR as `<cr>` and `<cr>-internal`. With
# `replication`, `galera` or `metrics` in its spec, mariadb-operator also
# creates `-primary`, `-secondary` and `-metrics`, and a hand re-pin that left
# them out of the inventory would stay green. Estate sees no rendered spec (the
# table is digests), so the guard reads where the spec is set: the
# Application's Helm values, under each module's `database`.


def app_with(edit) -> bytes:
    doc = yaml.safe_load(APP)
    edit(doc["spec"]["source"])
    return yaml.safe_dump(doc).encode()


def values(source):
    return source["helm"]["valuesObject"]


@pytest.mark.parametrize("key", ["replication", "galera", "metrics"])
@pytest.mark.parametrize("where", ["instance", "database"])
def test_a_mariadb_spec_that_makes_the_operator_create_more_services_is_red(key, where):
    def edit(source):
        db = values(source)["task-db"]["database"]
        (db["instance"] if where == "instance" else db)[key] = {"enabled": True}

    with pytest.raises(verdict.Red) as err:
        check(app=app_with(edit))
    assert f"`task-db.database` sets `{key}`" in str(err.value)
    assert "C-18 inventory" in str(err.value)


def test_a_mariadb_key_set_deep_inside_the_database_values_is_red():
    def edit(source):
        values(source)["iam-db"]["database"]["instance"]["storage"]["metrics"] = {"enabled": False}

    with pytest.raises(verdict.Red, match=r"`iam-db\.database` sets `metrics`"):
        check(app=app_with(edit))


def test_metrics_outside_a_database_does_not_touch_the_inventory():
    def edit(source):
        values(source)["gateway"]["metrics"] = {"enabled": True}

    check(app=app_with(edit))


def test_the_same_keys_in_helm_values_text_or_parameters_are_red():
    def text(source):
        source["helm"]["values"] = "project-db:\n  database:\n    galera: {enabled: true}\n"

    with pytest.raises(verdict.Red, match=r"`project-db\.database` sets `galera`"):
        check(app=app_with(text))

    def param(source):
        source["helm"]["parameters"] = [{"name": "iam-db.database.instance.replication.enabled", "value": "true"}]

    with pytest.raises(verdict.Red, match=r"parameter `iam-db\.database\.instance\.replication\.enabled`"):
        check(app=app_with(param))


def test_helm_value_files_are_red_because_the_mariadb_spec_cannot_be_read():
    def edit(source):
        source["helm"]["valueFiles"] = ["values-ha.yaml"]

    with pytest.raises(verdict.Red, match=r"`valueFiles`"):
        check(app=app_with(edit))


def test_helm_values_text_that_does_not_parse_is_red():
    def edit(source):
        source["helm"]["values"] = "a: [unclosed\n"

    with pytest.raises(verdict.Red, match=r"spec\.source\.helm\.values does not parse"):
        check(app=app_with(edit))


# ── in the job: drift reds C-18 only, and only on a run that reaches the rows ─
#
# Ruled 2026-11-03 (yaadgaar #549, option b). Inventory drift no longer fails
# the whole `verdict` job when the rows would run: the job answers `run=true`
# with `inventory=drift`, the front-door rows run, and `smoke.yaml`'s C-18 step
# fails on it (and no certificate is written, so the next poll asks again).
# Every outcome that would NOT run the rows stays a whole-job red, as before:
# otherwise drift on a waiting, red or certified epoch would read as a quiet
# `run=false`, which is a refusal lost. These replace two tests that pinned the
# old whole-job red on every outcome:
# `test_the_job_reads_the_committed_reference_by_default_and_d41_is_drift_against_it`
# and `test_inventory_drift_is_red_in_the_job_before_the_token_is_used`.

GREEN_D41 = {"S": SHA_D41, "P": "0.3.38", "K": K_D41C07F, "A": SHA_D41, "result": "green"}


def drifted() -> bytes:
    """d41's own reference with one inventory entry argocd does not render.

    The drift is on estate's side on purpose: a changed TABLE moves K, and the
    verdict would then be refused for its key rather than judged.
    """
    return d41_reference().replace(b'inventory = ["', f'inventory = ["search{HOST}:9000", "'.encode(), 1)


def test_the_job_passes_the_d41_world_with_its_own_lines(world):
    world.add_verdict(7, GREEN_D41)
    d = run(world)
    assert d.run and d.inventory == "ok"


def test_drift_on_a_green_uncertified_epoch_runs_the_rows_and_marks_c18_red(world):
    world.add_verdict(7, GREEN_D41)
    d = run(world, reference=None)  # the committed reference: d41 is drift against it
    assert d.run and d.inventory == "drift"
    assert "C-18 inventory" in d.summary and "`/Service//valkey` changed at argocd main" in d.summary


def test_drift_from_an_extra_inventory_entry_runs_the_rows_and_marks_c18_red(world):
    assert drifted() != d41_reference()
    world.add_verdict(7, GREEN_D41)
    d = run(world, reference=drifted())
    assert d.run and d.inventory == "drift"
    assert f"the inventory names `search{HOST}` but argocd main renders no such Service" in d.summary


@pytest.mark.parametrize("outcome", ["waiting", "red-verdict", "certified"])
def test_drift_on_an_outcome_that_runs_no_rows_is_still_a_whole_job_red(world, outcome):
    if outcome == "red-verdict":
        world.add_verdict(7, dict(GREEN_D41, result="red", clause="Clause A"))
    if outcome == "certified":
        world.add_verdict(7, GREEN_D41)
        world.add_cert(f"{K_D41C07F}-{SHA_D41}", 1)
    # The same world without drift is a QUIET run=false, so the red below is the drift's.
    assert not run(world).run
    with pytest.raises(verdict.Red, match=r"C-18 inventory.*\(and no rows run: "):
        run(world, reference=drifted())


def test_drift_keeps_a_refusal_the_job_already_had(world):
    with pytest.raises(verdict.Red, match="read token is empty.*; and the C-18 inventory"):
        run(world, verify_token="", reference=drifted())


def test_a_reference_that_does_not_parse_is_still_red_before_the_token_is_used(world):
    world.add_verdict(7, GREEN_D41)
    with pytest.raises(verdict.Red, match="reference.toml does not parse"):
        run(world, reference=b"[confinement\n")
    assert all(tok == OWN_TOKEN for _, tok in world.calls)


def test_main_hands_the_inventory_state_to_the_smoke_job(world, tmp_path, monkeypatch):
    world.add_verdict(7, GREEN_D41)
    out, summary = tmp_path / "out", tmp_path / "summary"
    (tmp_path / "reference.toml").write_bytes(drifted())
    monkeypatch.setattr(verdict, "REFERENCE_PATH", tmp_path / "reference.toml")
    env = {"GITHUB_REPOSITORY": "yadgarhq/estate", "GITHUB_REPOSITORY_ID": str(ESTATE_ID),
           "GITHUB_TOKEN": OWN_TOKEN, "VERDICT_TOKEN": VERIFY_TOKEN,
           "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary)}
    assert verdict.main(env, world) == 0
    assert "run=true\n" in out.read_text() and "inventory=drift\n" in out.read_text()
    assert "C-18 inventory" in summary.read_text()
