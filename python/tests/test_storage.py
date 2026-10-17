"""Real MariaDB/MySQL integration tests against an explicitly disposable DB.

Set O3CLOUDCENTRAL_TEST_DSN to mysql+pymysql://.../o3cloudcentral_test... . No SQLite or mock
database is accepted. Only tables defined by O3CloudCentral metadata are removed, and
both the requested and connected database names are checked before every reset.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import delete, insert, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from o3cloudcentral.storage import (StateRepository, devices, empty_state, grants,
                            metadata, reports, services, sites, tickets, validate_state)


def _assert_test_database(dsn: str) -> str:
    parsed = make_url(dsn)
    database = parsed.database or ""
    if parsed.drivername not in ("mysql+pymysql", "mariadb+pymysql") or not database.startswith("o3cloudcentral_test"):
        raise ValueError("Integration tests require a MariaDB/MySQL database starting with o3cloudcentral_test.")
    return database


def _reset_test_tables(repository: StateRepository, database: str) -> None:
    if not database.startswith("o3cloudcentral_test"):
        raise ValueError("Refusing cleanup outside an O3CloudCentral test database.")
    with repository.engine.connect() as conn:
        actual = conn.execute(text("SELECT DATABASE()")).scalar_one()
        if actual != database or not actual.startswith("o3cloudcentral_test"):
            raise ValueError("Connected database differs from the authorized test database.")
        conn.rollback()
        # Never disable foreign keys or delete arbitrary tables in the database.
        metadata.drop_all(conn)
        conn.commit()


@pytest.fixture
def repository():
    dsn = os.environ.get("O3CLOUDCENTRAL_TEST_DSN")
    if not dsn:
        pytest.skip("Set O3CLOUDCENTRAL_TEST_DSN to run real MariaDB integration tests.")
    database = _assert_test_database(dsn)
    instance = StateRepository(dsn)
    try:
        _reset_test_tables(instance, database)
        instance.initialize_schema()
        yield instance
    finally:
        try:
            _reset_test_tables(instance, database)
        finally:
            instance.close()


def legacy_state() -> dict:
    """Public fixture data including the null vectors written by old Go agents."""
    first = {
        "id": "vps_a", "name": "Cliente São Paulo 🟢", "endpoint": "vpn.example:2222",
        "listen": "10.20.0.20:2222", "cidrs": ["172.30.20.0/24"],
        "host_key": "ssh-ed25519 fixture-public-key-a\n", "gateway_hash": "b" * 64,
        "services": [
            {"id": "svc_b", "name": "HTTPS administração", "target": "172.30.20.10", "port": 443, "local_port": 20001, "protocol": "TCP", "type": "HTTPS"},
            {"id": "svc_a", "name": "Nginx laboratório", "target": "172.30.20.10", "port": 80, "local_port": 20000, "protocol": "TCP", "type": "HTTP"},
        ],
        "last_seen": "2026-10-16T12:00:00.123456789Z", "last_source": "10.20.0.20",
        "report": {"sessions": {"dev_a": 1}, "services": [{"id": "svc_a", "reachable": True, "checked_at": "2026-10-16T12:00:00Z"}], "version": "0.4.0-lab", "policy_revision": "c" * 64, "terminals": {"dev_a": {"hostname": "CAIXA-01", "local_ip": "192.168.50.10", "os": "windows", "agent_version": "0.4.0-lab"}}},
    }
    second = {
        "id": "vps_b", "name": "Cliente vazio", "endpoint": "vpn.example:2223",
        "listen": "0.0.0.0:2222", "cidrs": None, "automatic_targets": True,
        "host_key": "", "services": None, "last_seen": "0001-01-01T00:00:00Z",
        "report": {"sessions": None, "services": None, "version": ""},
    }
    devices_fixture = {
        "dev_a": {"id": "dev_a", "site_id": "vps_a", "name": "CAIXA-01", "hostname": "CAIXA-01", "local_ip": "192.168.50.10", "agent_version": "0.4.0-lab", "os": "windows", "automatic_name": True, "services": ["svc_a", "svc_b"], "public_key": "ssh-ed25519 fixture-terminal-key\n", "token_hash": "d" * 64, "revoked": False, "last_seen": "2026-10-16T12:00:00.123Z", "status": "conectado"},
        "dev_b": {"id": "dev_b", "site_id": "vps_b", "name": "Novo terminal", "services": None, "public_key": "", "revoked": False, "last_seen": "0001-01-01T00:00:00Z", "status": "aguardando instalação"},
    }
    tickets_fixture = {}
    for kind, object_id in (("agent", "dev_b"), ("gateway", "vps_b"), ("gateway-update", "vps_a")):
        hashed = hashlib.sha256(("fixture-" + kind).encode()).hexdigest()
        tickets_fixture[hashed] = {"hash": hashed, "kind": kind, "object_id": object_id, "expires": "2099-01-01T00:00:00Z"}
    return {"url": "https://10.20.0.10:8443", "admin_hash": "a" * 64,
            "sites": {"vps_a": first, "vps_b": second}, "devices": devices_fixture,
            "tickets": tickets_fixture}


def write_legacy(tmp_path, state: dict, name="legacy-state.json"):
    path = tmp_path / name
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def test_database_cleanup_guard_never_accepts_production_or_sqlite():
    for dsn in ("mysql+pymysql://user@localhost/o3cloudcentral", "mariadb+pymysql://user@localhost/customer", "sqlite:///o3cloudcentral_test.db", "mysql+pymysql://user@localhost/O3CLOUDCENTRAL_TEST", "mysql+pymysql://user@localhost/"):
        with pytest.raises(ValueError):
            _assert_test_database(dsn)
    assert _assert_test_database("mysql+pymysql://fixture@localhost/o3cloudcentral_test") == "o3cloudcentral_test"


def test_storage_rejects_other_database_engines():
    for dsn in ("sqlite://", "sqlite:///fixture.db", "postgresql://localhost/o3cloudcentral_test", "mysql://localhost/o3cloudcentral_test"):
        with pytest.raises(ValueError):
            StateRepository(dsn)


def test_exact_legacy_migration_null_order_unicode_and_dry_run(repository, tmp_path):
    state = legacy_state()
    path = write_legacy(tmp_path, state)
    summary = repository.import_legacy(path, dry_run=True)
    assert summary == {"sites": 2, "devices": 2, "services": 2, "tickets": 3, "dry_run": True}
    assert repository.read() == empty_state()
    applied = repository.import_legacy(path)
    assert applied["already_imported"] is False
    assert repository.read() == state
    # Recreating schema must not recreate/reset settings or drop existing rows.
    repository.initialize_schema()
    assert repository.read() == state
    with repository.engine.connect() as conn:
        assert len(conn.execute(select(sites)).all()) == 2
        assert len(conn.execute(select(services)).all()) == 2
        assert len(conn.execute(select(grants)).all()) == 2
        assert len(conn.execute(select(reports)).all()) == 2
        assert len(conn.execute(select(tickets)).all()) == 3


def test_repeat_migration_does_not_reset_live_changes(repository, tmp_path):
    original = legacy_state()
    path = write_legacy(tmp_path, original)
    repository.import_legacy(path)
    repository.transaction(lambda state: state["sites"]["vps_a"].update(name="Nome alterado depois da migração"))
    after = repository.read()
    assert repository.import_legacy(path)["already_imported"] is True
    assert repository.read() == after
    changed_source = copy.deepcopy(original)
    changed_source["sites"]["vps_a"]["name"] = "Outro arquivo antigo"
    with pytest.raises(ValueError):
        repository.import_legacy(write_legacy(tmp_path, changed_source, "different-source.json"))
    assert repository.read() == after


def test_import_and_initialization_refuse_nonempty_target(repository, tmp_path):
    state = legacy_state()
    repository.initialize(state)
    before = repository.read()
    with pytest.raises(ValueError):
        repository.initialize(state)
    with pytest.raises(ValueError):
        repository.import_legacy(write_legacy(tmp_path, state))
    assert repository.read() == before


def test_transaction_rolls_back_callback_validation_and_sql_writes(repository, monkeypatch):
    state = legacy_state()
    repository.initialize(state)

    def callback_failure(current):
        current["sites"]["vps_a"]["name"] = "must not persist"
        raise RuntimeError("fixture callback failure")
    with pytest.raises(RuntimeError, match="fixture callback failure"):
        repository.transaction(callback_failure)
    assert repository.read() == state

    def invalid_grant(current):
        current["devices"]["dev_b"]["services"] = ["svc_a"]
    with pytest.raises(ValueError):
        repository.transaction(invalid_grant)
    assert repository.read() == state

    persist = repository._persist
    def fail_after_sql(conn, previous, current):
        persist(conn, previous, current)
        raise RuntimeError("fixture failure after SQL changes")
    monkeypatch.setattr(repository, "_persist", fail_after_sql)
    with pytest.raises(RuntimeError, match="after SQL changes"):
        repository.transaction(lambda current: current["sites"]["vps_a"].update(name="written but uncommitted"))
    assert repository.read() == state


def test_database_lock_prevents_lost_updates_and_ticket_reuse(repository):
    state = legacy_state()
    repository.initialize(state)
    workers = 8
    gate = threading.Barrier(workers)
    ticket_hash = next(key for key, ticket in state["tickets"].items() if ticket["kind"] == "agent")

    def consume(_):
        gate.wait(timeout=20)
        def operation(current):
            if ticket_hash not in current["tickets"]:
                return False
            del current["tickets"][ticket_hash]
            return True
        return repository.transaction(operation)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        result = list(pool.map(consume, range(workers)))
    assert result.count(True) == 1 and result.count(False) == workers - 1

    def increment(_):
        def operation(current):
            site = current["sites"]["vps_a"]
            site["counter"] = site.get("counter", 0) + 1
        repository.transaction(operation)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(increment, range(32)))
    assert repository.read()["sites"]["vps_a"]["counter"] == 32
    # Mutating a returned result cannot change a committed database object.
    detached = repository.transaction(lambda current: current["sites"]["vps_a"])
    detached["counter"] = -1
    assert repository.read()["sites"]["vps_a"]["counter"] == 32


def test_composite_foreign_keys_reject_cross_client_grants_and_cascade(repository):
    state = legacy_state()
    state["sites"]["vps_b"]["services"] = [{"id": "svc_c", "name": "Outro cliente", "target": "172.30.30.10", "port": 80, "local_port": 20000, "protocol": "TCP", "type": "HTTP"}]
    state["devices"]["dev_b"]["services"] = ["svc_c"]
    repository.initialize(state)
    # Both possible fake site IDs are rejected: device ownership and service
    # ownership each have an independent composite foreign key in the database.
    for fake_site_id in ("vps_a", "vps_b"):
        with pytest.raises(IntegrityError):
            with repository.engine.begin() as conn:
                conn.execute(insert(grants).values(device_id="dev_a", service_id="svc_c", site_id=fake_site_id, position=9))
    assert repository.read() == state
    with repository.engine.begin() as conn:
        conn.execute(delete(sites).where(sites.c.id == "vps_a"))
    remaining = repository.read()
    assert set(remaining["sites"]) == {"vps_b"}
    assert set(remaining["devices"]) == {"dev_b"}
    assert remaining["sites"]["vps_b"] == state["sites"]["vps_b"]
    assert all(ticket["object_id"] in ("vps_b", "dev_b") for ticket in remaining["tickets"].values())
    with repository.engine.connect() as conn:
        assert len(conn.execute(select(services)).all()) == 1
        assert len(conn.execute(select(grants)).all()) == 1
        assert len(conn.execute(select(reports)).all()) == 1


def test_invalid_legacy_data_never_partially_imports(repository, tmp_path):
    state = legacy_state()
    state["devices"]["dev_b"]["services"] = ["svc_a"]
    with pytest.raises(ValueError):
        repository.import_legacy(write_legacy(tmp_path, state))
    assert repository.read() == empty_state()


def test_central_api_commits_telemetry_and_revocation_in_mariadb(repository, tmp_path):
    import asyncssh
    from fastapi.testclient import TestClient
    from o3cloudcentral.central import create_app, digest
    (tmp_path / "ca.crt").write_text("fixture-ca", encoding="utf-8")
    state = empty_state()
    state.update(url="https://central.example:8443", admin_hash=digest("fixture-password"))
    repository.initialize(state)
    auth = {"auth": ("admin", "fixture-password"), "headers": {"X-O3CloudCentral-Request": "1"}}
    app = create_app(repository, tmp_path, monitor=False)
    with TestClient(app, base_url="https://central.example:8443") as client:
        def post(path, body):
            result = client.post(path, json=body, **auth)
            assert result.status_code == 200, result.text
            return result.json()
        site = post("/api/admin/sites", {"name": "Teste MariaDB", "endpoint": "gateway.example:2222"})
        service = post(f"/api/admin/sites/{site['id']}/services", {"name": "Nginx", "target": "172.30.20.10", "port": 80, "type": "HTTP"})
        device = post("/api/admin/devices", {"site_id": site["id"], "services": [service["id"]]})
        bundle = post(f"/api/admin/sites/{site['id']}/bootstrap", {})
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        gateway = client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": key}).json()
        proxy = {"Authorization": "Bearer " + gateway["token"], "X-O3CloudCentral-Gateway": "1"}
        terminal_bundle = post(f"/api/admin/devices/{device['id']}/bootstrap", {})
        terminal_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        enrolled = client.post("/api/enroll", headers=proxy, json={"kind": "agent", "token": terminal_bundle["token"], "public_key": terminal_key, "hostname": "CAIXA-SQL", "transport": "ssh-policy-v1"})
        assert enrolled.status_code == 200, enrolled.text
        report = {"sessions": {device["id"]: 1}, "services": [], "version": "0.5.0-lab", "terminals": {device["id"]: {"hostname": "CAIXA-SQL", "local_ip": "192.168.50.20", "os": "windows", "agent_version": "0.5.0-lab"}}}
        synced = client.post("/api/gateway/sync", headers={"Authorization": proxy["Authorization"]}, json=report)
        assert synced.status_code == 200, synced.text
        committed = repository.read()
        assert committed["devices"][device["id"]]["local_ip"] == "192.168.50.20"
        assert committed["devices"][device["id"]]["status"] == "conectado"
        assert committed["sites"][site["id"]]["report"]["sessions"] == {device["id"]: 1}
        assert device["id"] in {d["id"] for d in synced.json()["devices"]}
        post(f"/api/admin/devices/{device['id']}/revoke", {})
        revoked = client.post("/api/gateway/sync", headers={"Authorization": proxy["Authorization"]}, json=report)
        assert revoked.status_code == 200 and revoked.json()["devices"] == []
        assert repository.read()["sites"][site["id"]]["report"]["sessions"] == {}
    # A fresh application/repository read obtains committed SQL state rather
    # than an in-memory copy retained by the first FastAPI process.
    with TestClient(create_app(repository, tmp_path, monitor=False), base_url="https://central.example:8443") as client:
        response = client.get("/api/admin/state", auth=auth["auth"])
        assert response.status_code == 200
        assert response.json()["devices"][device["id"]]["revoked"] is True


def test_reusable_link_storage_validates_scopes_counters_and_secret_free_metadata():
    state = legacy_state()
    hashed = hashlib.sha256(b"public-fixture-reusable-link").hexdigest()
    ticket = {"hash": hashed, "kind": "agent-link", "object_id": "vps_a",
              "id": "lnk_" + "1" * 24, "services": ["svc_a"],
              "created": "2026-10-16T12:00:00Z", "expires": None, "used_count": 0}
    state["tickets"][hashed] = ticket
    validate_state(state)
    ticket["expires"] = ""
    validate_state(state)
    for mutation in ({"token": "must-not-be-persisted"}, {"services": []},
                     {"services": ["missing"]}, {"used_count": True},
                     {"used_count": -1}, {"id": "unsafe-id"}):
        invalid = copy.deepcopy(state)
        invalid["tickets"][hashed].update(mutation)
        with pytest.raises(ValueError):
            validate_state(invalid)
    duplicate = copy.deepcopy(state)
    second_hash = hashlib.sha256(b"another-public-link-fixture").hexdigest()
    duplicate["tickets"][second_hash] = {**ticket, "hash": second_hash, "id": "lnk_" + "2" * 24}
    with pytest.raises(ValueError):
        validate_state(duplicate)
    duplicate["tickets"][second_hash]["platform"] = "debian"
    validate_state(duplicate)
    duplicate["tickets"][second_hash]["platform"] = "arm"
    with pytest.raises(ValueError):
        validate_state(duplicate)
    cross_tenant = copy.deepcopy(state)
    cross_tenant["tickets"][hashed]["object_id"] = "vps_b"
    with pytest.raises(ValueError):
        validate_state(cross_tenant)


def test_linux_and_windows_links_survive_mariadb_roundtrip(repository):
    state = legacy_state()
    for index, platform in enumerate(("windows", "debian")):
        hashed = hashlib.sha256(platform.encode()).hexdigest()
        state["tickets"][hashed] = {"hash":hashed, "kind":"agent-link", "object_id":"vps_a",
            "id":"lnk_"+str(index)*24, "services":["svc_a"], "created":"2026-10-17T12:00:00Z",
            "expires":None, "used_count":index, "platform":platform}
    repository.initialize(state)
    independent = StateRepository(os.environ["O3CLOUDCENTRAL_TEST_DSN"])
    try:
        persisted = independent.read()
        for platform in ("windows", "debian"):
            assert persisted["tickets"][hashlib.sha256(platform.encode()).hexdigest()]["platform"] == platform
        repository.transaction(lambda current: current["tickets"].pop(hashlib.sha256(b"debian").hexdigest()))
        assert hashlib.sha256(b"windows").hexdigest() in independent.read()["tickets"]
    finally:
        independent.close()


def test_auth_users_and_hashed_sessions_persist_across_mariadb_instances(repository, tmp_path):
    from fastapi.testclient import TestClient
    from o3cloudcentral.central import create_app
    from o3cloudcentral.central_auth import COOKIE
    from o3cloudcentral.crypto import hash_admin_password
    from o3cloudcentral.central import digest
    state = legacy_state()
    hashed = hash_admin_password('public-test-account-password-123')
    state['users'] = {'technician':{'password_hash':hashed,'created':'2026-10-17T12:00:00Z'}}
    raw = 't' * 43
    session_id = digest(raw)
    state['sessions'] = {session_id:{'username':'technician','credential':digest(hashed),'expires':'2099-10-17T12:00:00Z'}}
    repository.initialize(state)
    independent = StateRepository(os.environ['O3CLOUDCENTRAL_TEST_DSN'])
    try:
        assert independent.read() == state
        (tmp_path/'ca.crt').write_text('public-fixture')
        with TestClient(create_app(independent, tmp_path, monitor=False), base_url='https://central.example') as second_app:
            headers = {'Cookie':COOKIE+'='+raw}
            assert second_app.get('/api/auth/me', headers=headers).json() == {'username':'technician'}
            repository.transaction(lambda current:current['sessions'].pop(session_id))
            assert second_app.get('/api/auth/me', headers=headers).status_code == 401
        assert not independent.read().get('sessions')
        assert independent.read()['users']['technician']['password_hash'] == hashed
    finally:
        independent.close()


def test_reusable_link_enrollment_is_atomic_and_persists_across_mariadb_instances(repository, tmp_path):
    from fastapi.testclient import TestClient
    from o3cloudcentral.central import create_app, digest
    from test_central import AUTH, gateway_enroll, new_service, new_site, post, public_key
    (tmp_path / "ca.crt").write_text("fixture-ca", encoding="utf-8")
    (tmp_path / "O3CloudCentral.exe").write_bytes(b"MZ-public-test-fixture")
    state = empty_state()
    state.update(url="https://central.example:8443", admin_hash=digest("fixture-password"))
    repository.initialize(state)
    with TestClient(create_app(repository, tmp_path, monitor=False), base_url=state["url"]) as client:
        site = new_site(client)
        service = new_service(client, site)
        gateway = gateway_enroll(client, site)
        link = post(client, f"/api/admin/sites/{site['id']}/install-link", {"services": [service["id"]]})
        token = link["url"].rsplit("/", 1)[-1]
        headers = {"Authorization": "Bearer " + gateway["token"], "X-O3CloudCentral-Gateway": "1"}
        def enroll(key):
            return client.post("/api/enroll", headers=headers, json={"kind": "agent", "token": token,
                "public_key": key, "hostname": "SAME-SQL-HOST", "transport": "ssh-policy-v1"})
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(enroll, [public_key() for _ in range(6)]))
        assert all(result.status_code == 200 for result in results), [result.text for result in results]
        assert len({result.json()["id"] for result in results}) == 6
        assert len({result.json()["token"] for result in results}) == 6
        repeated_key = public_key()
        with ThreadPoolExecutor(max_workers=4) as pool:
            repeated = list(pool.map(enroll, [repeated_key] * 4))
        assert sorted(result.status_code for result in repeated) == [200, 403, 403, 403]
        committed = repository.read()
        assert len(committed["devices"]) == 7
        assert committed["tickets"][digest(token)]["used_count"] == 7
        assert token not in json.dumps(committed)
        assert all(device["services"] == [service["id"]] for device in committed["devices"].values())
        # A second SQLAlchemy engine proves metadata and terminal credentials
        # survive independently of this FastAPI process and its connection pool.
        independent = StateRepository(os.environ["O3CLOUDCENTRAL_TEST_DSN"])
        try:
            assert independent.read() == committed
        finally:
            independent.close()
        with repository.engine.connect() as conn:
            assert len(conn.execute(select(grants)).all()) == 7
            assert len(conn.execute(select(tickets)).all()) == 1
        view = client.get("/api/admin/state", auth=AUTH["auth"])
        assert view.json()["sites"][site["id"]]["installation_link"]["installation_count"] == 7
        assert token not in view.text and digest(token) not in view.text
        revoked = client.delete(f"/api/admin/sites/{site['id']}/install-link", **AUTH)
        assert revoked.status_code == 200
        assert repository.read()["devices"] == committed["devices"]
        assert repository.read()["tickets"] == {}
        assert enroll(public_key()).status_code == 403
        # Removing the customer cascades persisted terminals/grants as usual.
        deleted = client.delete(f"/api/admin/sites/{site['id']}", **AUTH)
        assert deleted.status_code == 200
        with repository.engine.connect() as conn:
            assert len(conn.execute(select(devices)).all()) == 0
            assert len(conn.execute(select(grants)).all()) == 0
