"""Explicit reinstallation rotates a retained customer's firewall only on enroll."""
import base64
import json
import re
import shlex
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from o3cloudcentral.central import ZERO_TIME, digest, now, stamp
from o3cloudcentral.storage import validate_state
from test_central import (AUTH, agent_enroll, gateway_enroll, lab, new_device,
                          new_service, new_site, post, public_key)
from test_storage import repository


def command_bundle(command):
    inner = shlex.split(command)[2]
    encoded = re.search(r'printf %s (\S+) \| openssl enc -base64 -d -A > "\$edge_tmp/enrollment.json"', inner)
    assert encoded, "The fresh installer must receive an enrollment bundle"
    return json.loads(base64.b64decode(shlex.split(encoded.group(1))[0]))


def reinstall(client, site):
    response = post(client, f"/api/admin/sites/{site['id']}/reinstall-command", {})
    return response, command_bundle(response["command"])


def sync(client, gateway, sessions=None):
    return client.post("/api/gateway/sync", headers={"Authorization": "Bearer " + gateway["token"]},
                       json={"sessions": sessions or {}, "services": [], "version": "fixture"})


def test_reinstall_command_is_fresh_guarded_and_preserves_live_gateway(lab):
    client, repository, _ = lab
    site = new_site(client)
    gateway = gateway_enroll(client, site)
    assert sync(client, gateway).status_code == 200
    before = repository.read()
    result, bundle = reinstall(client, site)
    assert set(result) == {"command", "expires_at", "sha256", "platform"}
    assert result["platform"] == "FreeBSD 14 amd64" and result["sha256"] in result["command"]
    assert '[ ! -e /usr/local/etc/o3cloudcentral/config.json ]' in result["command"]
    assert '--replace-client ' + site['id'] in result['command']
    assert 'tar -xOf "$edge_tmp/package.pkg" /usr/local/sbin/o3cloudcentral-uninstall' in result['command']
    assert result['command'].index('sha256 -q') < result['command'].index('tar -xOf') < result['command'].index('--replace-client') < result['command'].index('pkg add -f')
    assert " enroll --bundle " in result["command"]
    assert "configure-gateway" not in result["command"] and "edge_dirty=1" not in result["command"]
    assert bundle["kind"] == "gateway" and bundle["listen"] == "0.0.0.0:2222"
    after = repository.read()
    assert after["sites"] == before["sites"] and after["devices"] == before["devices"]
    ticket = after["tickets"][digest(bundle["token"])]
    assert ticket == {"hash": digest(bundle["token"]), "kind": "gateway-reinstall",
                      "object_id": site["id"], "expires": result["expires_at"]}
    validate_state(after)
    assert bundle["token"] not in json.dumps(after)
    package = client.get(f"/api/install/pfsense/{bundle['token']}/package")
    assert package.status_code == 200 and package.content == b"fixture-package"
    # Preparing a replacement must not interrupt the still-running firewall.
    assert sync(client, gateway).status_code == 200
    update = post(client, f"/api/admin/sites/{site['id']}/update-command", {})
    assert "configure-gateway" in update["command"] and "edge_dirty=1" in update["command"]


def test_successful_reinstall_rotates_only_its_gateway_and_preserves_terminal_grants(lab):
    client, repository, _ = lab
    site, other = new_site(client), new_site(client, "Other", "other.example:2222")
    service = new_service(client, site)
    gateway, other_gateway = gateway_enroll(client, site), gateway_enroll(client, other)
    device = new_device(client, site, service)
    assert agent_enroll(client, device, proxy=gateway)[0].status_code == 200
    assert sync(client, gateway, {device["id"]: 1}).status_code == 200
    post(client, f"/api/admin/sites/{site['id']}/update-command", {})
    post(client, f"/api/admin/sites/{other['id']}/update-command", {})
    link = post(client, f"/api/admin/sites/{site['id']}/install-link", {"services": [service["id"]]})
    _, bundle = reinstall(client, site)
    before = repository.read()
    key = public_key()
    response = client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": key})
    assert response.status_code == 200, response.text
    replacement = response.json()
    assert replacement["id"] == site["id"] and replacement["token"] != gateway["token"]
    after = repository.read()
    validate_state(after)
    current = after["sites"][site["id"]]
    assert current["host_key"] == key and current["gateway_hash"] == digest(replacement["token"])
    assert current["host_key"] != before["sites"][site["id"]]["host_key"]
    assert current["last_seen"] == ZERO_TIME and current["last_source"] == ""
    assert current["report"] == {"sessions": {}, "services": [], "version": ""}
    assert current["services"] == before["sites"][site["id"]]["services"]
    assert after["devices"] == before["devices"]
    assert after["sites"][other["id"]] == before["sites"][other["id"]]
    assert all(not (ticket["object_id"] == site["id"] and ticket["kind"] in ("gateway-update", "gateway-reinstall"))
               for ticket in after["tickets"].values())
    assert any(ticket["object_id"] == other["id"] and ticket["kind"] == "gateway-update" for ticket in after["tickets"].values())
    assert after["tickets"][digest(link["url"].rsplit("/", 1)[-1])] == before["tickets"][digest(link["url"].rsplit("/", 1)[-1])]
    assert sync(client, gateway).status_code == 403
    assert sync(client, other_gateway).status_code == 200
    snapshot = sync(client, replacement)
    assert snapshot.status_code == 200
    assert snapshot.json()["devices"][0]["id"] == device["id"]
    assert snapshot.json()["devices"][0]["services"][0]["id"] == service["id"]
    assert client.get(f"/api/install/pfsense/{bundle['token']}/package").status_code == 403
    assert client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": public_key()}).status_code == 403


def test_reinstall_ticket_rejects_wrong_kind_proxy_and_expiry_without_mutation(lab):
    client, repository, _ = lab
    site, other = new_site(client), new_site(client, "Other", "other.example:2222")
    gateway_enroll(client, site)
    wrong_gateway = gateway_enroll(client, other)
    _, bundle = reinstall(client, site)
    before = repository.read()
    data = {"kind": "gateway", "token": bundle["token"], "public_key": public_key()}
    relay = {"X-O3CloudCentral-Gateway": "1", "Authorization": "Bearer " + wrong_gateway["token"]}
    assert client.post("/api/enroll", json=data, headers=relay).status_code == 403
    assert client.get(f"/api/install/pfsense/{bundle['token']}/package", headers=relay).status_code == 403
    assert client.post("/api/enroll", json={**data, "kind": "agent"}).status_code == 403
    assert repository.read() == before
    repository.transaction(lambda state: state["tickets"][digest(bundle["token"])].update(expires=stamp(now() - timedelta(seconds=1))))
    expired = repository.read()
    assert client.post("/api/enroll", json=data).status_code == 403
    assert client.get(f"/api/install/pfsense/{bundle['token']}/package").status_code == 403
    assert repository.read() == expired


def test_reinstall_generation_rotates_ticket_only_and_customer_delete_cleans_it(lab):
    client, repository, _ = lab
    site = new_site(client)
    gateway = gateway_enroll(client, site)
    _, first = reinstall(client, site)
    _, second = reinstall(client, site)
    assert first["token"] != second["token"]
    assert digest(first["token"]) not in repository.read()["tickets"]
    assert client.get(f"/api/install/pfsense/{first['token']}/package").status_code == 403
    assert sync(client, gateway).status_code == 200
    assert client.delete(f"/api/admin/sites/{site['id']}", **AUTH).status_code == 200
    assert repository.read()["tickets"] == {}
    assert client.get(f"/api/install/pfsense/{second['token']}/package").status_code == 403


def test_reinstall_requires_admin_csrf_valid_body_site_and_available_package(lab):
    client, repository, central = lab
    site = new_site(client)
    gateway_enroll(client, site)
    path = f"/api/admin/sites/{site['id']}/reinstall-command"
    before = repository.read()
    assert client.post(path, json={}).status_code == 401
    assert client.post(path, json={}, auth=AUTH["auth"]).status_code == 403
    assert client.post(path, json={"unexpected": True}, **AUTH).status_code == 400
    assert client.post("/api/admin/sites/missing/reinstall-command", json={}, **AUTH).status_code == 400
    central.package.unlink()
    assert client.post(path, json={}, **AUTH).status_code == 503
    assert repository.read() == before


def test_invalid_portal_csr_cannot_replace_live_gateway(lab):
    client, repository, _ = lab
    site = new_site(client)
    gateway = gateway_enroll(client, site)
    _, bundle = reinstall(client, site)
    before = repository.read()
    response = client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"],
        "public_key": public_key(), "portal_csr": "invalid-csr"})
    assert response.status_code == 403
    assert repository.read() == before
    assert sync(client, gateway).status_code == 200


def test_concurrent_reinstall_ticket_has_exactly_one_winning_gateway(lab):
    client, repository, _ = lab
    site = new_site(client)
    gateway_enroll(client, site)
    _, bundle = reinstall(client, site)
    def enroll(key):
        return client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": key})
    keys = [public_key() for _ in range(4)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(enroll, keys))
    assert sorted(result.status_code for result in results) == [200, 403, 403, 403]
    winner = next(index for index, result in enumerate(results) if result.status_code == 200)
    current = repository.read()["sites"][site["id"]]
    assert current["host_key"] == keys[winner]
    assert current["gateway_hash"] == digest(results[winner].json()["token"])


def test_reinstall_ticket_and_atomic_identity_rotation_persist_in_mariadb(repository, tmp_path):
    from fastapi.testclient import TestClient
    from o3cloudcentral.central import create_app
    from o3cloudcentral.central_artifacts import DEFAULT_PFSENSE_PACKAGE
    from o3cloudcentral.storage import empty_state
    (tmp_path / "ca.crt").write_text("fixture-ca", encoding="utf-8")
    (tmp_path / DEFAULT_PFSENSE_PACKAGE).write_bytes(b"fixture-package")
    state = empty_state()
    state.update(url="https://central.example", admin_hash=digest("fixture-password"))
    repository.initialize(state)
    with TestClient(create_app(repository, tmp_path, monitor=False), base_url=state["url"]) as client:
        site = new_site(client)
        service = new_service(client, site)
        device = new_device(client, site, service)
        old_gateway = gateway_enroll(client, site)
        before = repository.read()
        _, bundle = reinstall(client, site)
        stored = repository.read()
        assert stored["sites"] == before["sites"]
        assert stored["tickets"][digest(bundle["token"])]["kind"] == "gateway-reinstall"
        key = public_key()
        response = client.post("/api/enroll", json={"kind": "gateway", "token": bundle["token"], "public_key": key})
        assert response.status_code == 200, response.text
        committed = repository.read()
        assert digest(bundle["token"]) not in committed["tickets"]
        assert committed["devices"][device["id"]] == before["devices"][device["id"]]
        assert committed["sites"][site["id"]]["gateway_hash"] == digest(response.json()["token"])
        assert committed["sites"][site["id"]]["host_key"] == key
        assert sync(client, old_gateway).status_code == 403
    # Recreating the app must authenticate only the newly committed identity.
    with TestClient(create_app(repository, tmp_path, monitor=False), base_url=state["url"]) as client:
        assert sync(client, response.json()).status_code == 200
        assert sync(client, old_gateway).status_code == 403
        assert client.get(f"/api/install/pfsense/{bundle['token']}/package").status_code == 403
