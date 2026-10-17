"""API regression tests. MemoryRepository is a test-only transaction fixture.

The deployed application requires StateRepository/MariaDB; no JSON/SQLite runtime
fallback is provided by these tests.
"""
import concurrent.futures
import asyncio
import copy
import json
import struct
import threading
from datetime import timedelta

import asyncssh
import pytest
from fastapi.testclient import TestClient

from edgehub.central import create_app, digest, identity, now, stamp
from edgehub.common import desired_snapshot
from edgehub.central_artifacts import DEFAULT_PFSENSE_PACKAGE


class MemoryRepository:
    def __init__(self):
        self.state = {"url": "https://10.20.0.10:8443", "admin_hash": "test-hash", "sites": {}, "devices": {}, "tickets": {}}
        self.lock = threading.RLock()

    def read(self):
        with self.lock:
            return copy.deepcopy(self.state)

    def transaction(self, callback):
        with self.lock:
            state = copy.deepcopy(self.state)
            result = callback(state)
            self.state = state
            return result


def public_key():
    return asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()


@pytest.fixture
def lab(tmp_path, monkeypatch):
    import edgehub.central as central
    monkeypatch.setattr(central, "check_admin_password", lambda hashed, password: hashed == "test-hash" and password == "fixture-password")
    (tmp_path / "ca.crt").write_text("fixture-ca")
    (tmp_path / "O3CloudCentral.exe").write_bytes(b"MZfixture-not-executable")
    (tmp_path / DEFAULT_PFSENSE_PACKAGE).write_bytes(b"fixture-package")
    repository = MemoryRepository()
    app = create_app(repository, tmp_path, monitor=False)
    with TestClient(app, base_url="https://central.example") as client:
        yield client, repository, app.state.central


AUTH = {"auth": ("admin", "fixture-password"), "headers": {"X-EdgeHub-Request": "1"}}


def post(client, path, body):
    response = client.post(path, json=body, **AUTH)
    assert response.status_code == 200, response.text
    return response.json()


def new_site(client, name="First", endpoint="vpn.example:2222"):
    return post(client, "/api/admin/sites", {"name": name, "endpoint": endpoint})


def new_service(client, site, name="Nginx", target="172.30.20.10", port=80):
    return post(client, f"/api/admin/sites/{site['id']}/services", {"name": name, "target": target, "port": port, "type": "HTTP"})


def new_device(client, site, service):
    return post(client, "/api/admin/devices", {"site_id": site["id"], "services": [service["id"]]})


def gateway_enroll(client, site):
    bundle = post(client, f"/api/admin/sites/{site['id']}/bootstrap", {})
    result = client.post("/api/enroll", json={"token": bundle["token"], "kind": "gateway", "public_key": public_key()})
    assert result.status_code == 200, result.text
    return result.json()


def agent_enroll(client, device, *, proxy=None, hostname="CAIXA-01"):
    bundle = post(client, f"/api/admin/devices/{device['id']}/bootstrap", {})
    headers = {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer " + proxy["token"]} if proxy else {}
    response = client.post("/api/enroll", headers=headers, json={"token": bundle["token"], "kind": "agent", "public_key": public_key(), "hostname": hostname, "transport": "ssh-policy-v1"})
    return response, bundle


def test_auth_csrf_and_input_contract(lab):
    client, repository, _ = lab
    assert client.get("/api/admin/state").status_code == 401
    assert client.post("/api/admin/sites", json={}, auth=AUTH["auth"]).status_code == 403
    assert client.post("/api/admin/sites", json={}, auth=AUTH["auth"], headers={"X-EdgeHub-Request": "1", "Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/admin/sites", content="{}", **AUTH).status_code == 415
    assert client.post("/api/admin/sites", json={"surprise": "field"}, **AUTH).status_code == 400
    assert client.post("/api/admin/sites", json={"name": "x", "endpoint": "vpn.example:2222", "listen": "10.20.0.20"}, **AUTH).status_code == 400
    assert client.post("/api/admin/sites", content=b'{"name":"x"}' + b" " * (128 << 10), headers={**AUTH["headers"], "Content-Type": "application/json"}, auth=AUTH["auth"]).status_code == 413
    assert not repository.read()["sites"]
    assert client.get("/healthz").json()["version"] == "0.6.6"
    assert client.get("/api/admin/state", headers={"Authorization": "Basic " + __import__("base64").b64encode("não:senha".encode()).decode()}).status_code == 401
    assert client.post("/api/admin/sites", content=b'{"name":"\\ud800","endpoint":"vpn.example:2222"}', headers={**AUTH["headers"], "Content-Type": "application/json"}, auth=AUTH["auth"]).status_code == 400


def test_crud_cascade_and_revision_ack(lab):
    client, repository, central = lab
    site = new_site(client)
    other = new_site(client, "Other", "vpn.example:2223")
    service = new_service(client, site)
    second = new_service(client, site, "HTTPS", port=443)
    outside = new_service(client, other, "Other", target="172.30.30.10")
    device = new_device(client, site, service)
    assert service["local_port"] == 20000 and second["local_port"] == 20001
    assert client.post("/api/admin/devices", json={"site_id": site["id"], "services": [outside["id"]]}, **AUTH).status_code == 400
    gateway = gateway_enroll(client, site)
    response, _ = agent_enroll(client, device, proxy=gateway)
    assert response.status_code == 200
    before = desired_snapshot(repository.read(), repository.read()["sites"][site["id"]])
    repository.transaction(lambda state: state["sites"][site["id"]].update(last_seen=stamp(), report={"sessions": {}, "services": [], "version": "fixture", "policy_revision": before["revision"]}))
    result = client.delete(f"/api/admin/sites/{site['id']}/services/{service['id']}", **AUTH)
    assert result.status_code == 200
    state = repository.read()
    assert state["devices"][device["id"]]["services"] == []
    assert state["sites"][site["id"]]["cidrs"] == ["172.30.20.10/32"]
    after = desired_snapshot(state, state["sites"][site["id"]])
    assert before["revision"] != after["revision"]
    view = central.state_view(state)
    assert view["sites"][site["id"]]["policy_sync"] == "pending"
    assert client.delete(f"/api/admin/sites/{site['id']}/services/{outside['id']}", **AUTH).status_code == 404
    assert client.delete(f"/api/admin/sites/{site['id']}", **AUTH).status_code == 200
    state = repository.read()
    assert device["id"] not in state["devices"] and site["id"] not in state["sites"]
    assert other["id"] in state["sites"]
    assert client.post("/api/gateway/sync", json={"sessions": {}, "services": [], "version": "fixture"}, headers={"Authorization": "Bearer " + gateway["token"]}).status_code == 403


def test_enrollment_one_use_and_gateway_scope(lab):
    client, repository, _ = lab
    first, second = new_site(client), new_site(client, "Second", "vpn.example:2223")
    first_service, second_service = new_service(client, first), new_service(client, second)
    first_device, second_device = new_device(client, first, first_service), new_device(client, second, second_service)
    gateway = gateway_enroll(client, first)
    gateway2 = gateway_enroll(client, second)
    wrong, bundle = agent_enroll(client, second_device, proxy=gateway)
    assert wrong.status_code == 403
    assert digest(bundle["token"]) in repository.read()["tickets"]
    key = public_key()
    payload = {"token": bundle["token"], "kind": "agent", "public_key": key, "hostname": "PC-2", "transport": "ssh-policy-v1"}
    proxy_headers = {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer " + gateway2["token"]}
    good = client.post("/api/enroll", json=payload, headers=proxy_headers)
    assert good.status_code == 200
    assert client.post("/api/enroll", json=payload, headers=proxy_headers).status_code == 403
    first_bundle = post(client, f"/api/admin/devices/{first_device['id']}/bootstrap", {})
    race_payload = {"token": first_bundle["token"], "kind": "agent", "public_key": public_key()}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(lambda _: client.post("/api/enroll", json=race_payload).status_code, range(4)))
    assert statuses.count(200) == 1 and statuses.count(403) == 3


def test_report_tenant_boundaries_metadata_and_presence(lab):
    client, repository, central = lab
    first, second = new_site(client), new_site(client, "Second", "vpn.example:2223")
    first_service, second_service = new_service(client, first), new_service(client, second)
    first_device, second_device = new_device(client, first, first_service), new_device(client, second, second_service)
    gateway = gateway_enroll(client, first)
    gateway_enroll(client, second)
    assert agent_enroll(client, first_device, proxy=gateway)[0].status_code == 200
    assert agent_enroll(client, second_device)[0].status_code == 200
    report = {"sessions": {first_device["id"]: 1, second_device["id"]: 1, "invented": 1}, "services": [{"id": first_service["id"], "reachable": True, "checked_at": stamp()}, {"id": second_service["id"], "reachable": True, "checked_at": stamp()}], "version": "0.5.0-lab", "terminals": {first_device["id"]: {"hostname": "LOJA-01", "local_ip": "192.168.50.22", "agent_version": "0.5.0-lab", "os": "windows"}, second_device["id"]: {"hostname": "FAKE-OTHER"}}}
    response = client.post("/api/gateway/sync", json=report, headers={"Authorization": "Bearer " + gateway["token"]})
    assert response.status_code == 200
    state = repository.read()
    assert state["sites"][first["id"]]["report"]["sessions"] == {first_device["id"]: 1}
    assert state["devices"][first_device["id"]]["hostname"] == "LOJA-01"
    assert state["devices"][second_device["id"]]["hostname"] == "CAIXA-01"
    central.probes[first["id"]] = {"key": central.probe_key(state["sites"][first["id"]]), "verified": True, "checked_at": stamp(), "address": first["endpoint"], "reason": "fixture"}
    view = central.state_view(state)
    assert view["devices"][first_device["id"]]["online"] is True
    assert view["sites"][first["id"]]["services"][0]["availability"] == "accessible"
    assert "gateway_hash" not in view["sites"][first["id"]]
    assert "token_hash" not in view["devices"][first_device["id"]]
    state["sites"][first["id"]]["last_seen"] = stamp(now() - timedelta(seconds=16))
    stale = central.state_view(state)
    assert stale["devices"][first_device["id"]]["online"] is False
    assert stale["sites"][first["id"]]["gateway_status"]["online"] is False
    assert stale["sites"][first["id"]]["services"][0]["availability"] == "unverified"
    assert identity({"hostname": "PC\nFAKE"}) is None
    assert identity({"local_ip": "127.0.0.1"}) is None
    assert identity({"hostname": "PC", "token": "untrusted"}) is None


def test_online_installer_and_ticket_cancellation(lab):
    client, repository, _ = lab
    site = new_site(client)
    service = new_service(client, site)
    device = new_device(client, site, service)
    gateway = gateway_enroll(client, site)
    other = new_site(client, "Other", "other.example:2222")
    other_gateway = gateway_enroll(client, other)
    link = post(client, f"/api/admin/devices/{device['id']}/install-link", {})
    assert link["url"].startswith("https://vpn.example:2222/install/windows/")
    token = link["url"].rsplit("/", 1)[-1]
    headers = {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer " + gateway["token"]}
    wrong = {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer " + other_gateway["token"]}
    assert client.get(f"/install/windows/{token}", headers=wrong).status_code == 403
    page = client.get(f"/install/windows/{token}", headers=headers)
    assert page.status_code == 200 and "Baixar instalador" in page.text
    assert '<title>Instalar O3 Cloud Central</title>' in page.text
    assert 'src="/brand/logo.png"' in page.text
    response = client.get(f"/install/windows/{token}/installer.exe", headers=headers)
    assert response.status_code == 200
    assert 'filename="O3CloudCentral-setup.exe"' in response.headers["Content-Disposition"]
    payload = response.content
    assert payload[-8:] == b"EHUB001!"
    length = struct.unpack("<Q", payload[-16:-8])[0]
    bundle = json.loads(payload[-16-length:-16])
    assert bundle["url"] == "https://vpn.example:2222" and bundle["token"] == token
    assert digest(token) in repository.read()["tickets"]
    assert client.post(f"/api/admin/devices/{device['id']}/revoke", json={}, **AUTH).status_code == 200
    assert client.get(f"/install/windows/{token}", headers=headers).status_code == 403


def test_brand_assets_are_real_public_images_and_panel_keeps_auth(lab):
    client, _, central = lab
    logo = client.get("/brand/logo.png")
    assert logo.status_code == 200 and logo.headers["content-type"].startswith("image/png")
    assert logo.content == central.logo.read_bytes()
    assert logo.content.startswith(b"\x89PNG\r\n\x1a\n")
    favicon = client.get("/favicon.ico?v=6")
    assert favicon.status_code == 200 and favicon.content == central.icon.read_bytes()
    anonymous = client.get("/", follow_redirects=False)
    assert anonymous.status_code == 303 and anonymous.headers['location'] == '/login'
    assert 'WWW-Authenticate' not in anonymous.headers
    login = client.post('/api/auth/login', json={'username':'admin', 'password':'fixture-password'}, headers=AUTH['headers'])
    assert login.status_code == 200
    panel = client.get("/")
    assert panel.status_code == 200 and '<title>O3 Cloud Central · Clientes</title>' in panel.text
    assert client.get("/healthz").json()["service"] == "O3 Cloud Central"


def test_bootstrap_commands_and_download_tickets(lab):
    client, repository, _ = lab
    site = new_site(client)
    command = post(client, f"/api/admin/sites/{site['id']}/install-command", {})
    assert command["command"].startswith("/bin/sh -c ")
    assert command["sha256"] in command["command"]
    assert "https://10.20.0.10:8443/api/install/pfsense/" in command["command"]
    ticket = next(iter(repository.read()["tickets"].values()))
    assert ticket["kind"] == "gateway"
    assert client.post(f"/api/admin/sites/{site['id']}/update-command", json={}, **AUTH).status_code == 400
    gateway_enroll(client, site)
    update = post(client, f"/api/admin/sites/{site['id']}/update-command", {})
    assert "configure-gateway" in update["command"]
    assert "edge_dirty=1" in update["command"]
    assert client.post(f"/api/admin/sites/{site['id']}/install-command", json={}, **AUTH).status_code == 400


def test_pinned_probe_checks_server_signature_and_listener(lab):
    _, _, central = lab

    async def exercise():
        key = asyncssh.generate_private_key("ssh-ed25519")

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

        async with await asyncssh.create_server(Server, "127.0.0.1", 0, server_host_keys=[key]) as listener:
            site = {"endpoint": f"127.0.0.1:{listener.get_port()}", "listen": "0.0.0.0:2222", "host_key": key.export_public_key().decode()}
            proof = await central.probe(site)
            assert proof["verified"] is True
            site["host_key"] = public_key()
            proof = await central.probe(site)
            assert proof["verified"] is False
        proof = await central.probe(site)
        assert proof["verified"] is False

    asyncio.run(exercise())


def test_portal_csr_is_scoped_and_keeps_private_key_local(tmp_path):
    from cryptography import x509
    from edgehub.crypto import initialize_pki, new_gateway_portal_csr, new_key
    initialize_pki(tmp_path, ["central.example"])
    repository = MemoryRepository()
    repository.state["admin_hash"] = digest("test-password")
    app = create_app(repository, tmp_path, monitor=False)
    auth = {"auth": ("admin", "test-password"), "headers": {"X-EdgeHub-Request": "1"}}
    with TestClient(app, base_url="https://central.example") as client:
        site = client.post("/api/admin/sites", json={"name": "CSR client", "endpoint": "gateway.example:2222"}, **auth).json()
        bundle = client.post(f"/api/admin/sites/{site['id']}/bootstrap", json={}, **auth).json()
        csr, private = new_gateway_portal_csr()
        response = client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": new_key()[1], "portal_csr": csr})
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["portal_url"] == "https://gateway.example:2222"
        assert body["portal_listen"] == "0.0.0.0:2222"
        assert "PRIVATE KEY" not in response.text and private not in response.text
        cert = x509.load_pem_x509_certificate(body["portal_cert"].encode())
        assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == ["gateway.example"]
        assert client.post("/api/gateway/portal", json={"csr": csr}).status_code == 403
        new_csr, _ = new_gateway_portal_csr()
        renewed = client.post("/api/gateway/portal", json={"csr": new_csr}, headers={"Authorization": "Bearer " + body["token"]})
        assert renewed.status_code == 200
        before = repository.read()
        assert client.post("/api/gateway/portal", json={"csr": "invalid"}, headers={"Authorization": "Bearer " + body["token"]}).status_code == 400
        assert repository.read() == before


def test_password_rotation_and_initial_secret_cleanup(tmp_path):
    (tmp_path / "ca.crt").write_text("fixture-ca")
    (tmp_path / "admin-password.txt").write_text("test-password")
    repository = MemoryRepository()
    repository.state["admin_hash"] = digest("test-password")
    app = create_app(repository, tmp_path, monitor=False)
    auth = {"auth": ("admin", "test-password"), "headers": {"X-EdgeHub-Request": "1"}}
    with TestClient(app, base_url="https://central.example") as client:
        bad = client.post("/api/admin/account/password", json={"current_password": "wrong-password", "new_password": "new-password-1234"}, **auth)
        assert bad.status_code == 400
        good = client.post("/api/admin/account/password", json={"current_password": "test-password", "new_password": "new-password-1234"}, **auth)
        assert good.status_code == 200 and good.json()["reauthenticate"] is True
        assert not (tmp_path / "admin-password.txt").exists()
        assert client.get("/api/admin/state", auth=auth["auth"]).status_code == 401
        assert client.get("/api/admin/state", auth=("admin", "new-password-1234")).status_code == 200
