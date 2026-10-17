"""Reusable links enroll independent terminals; they never share credentials."""
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import struct
from datetime import timedelta
import pytest

from test_central import (AUTH, agent_enroll, gateway_enroll, lab, new_device,
                          new_service, new_site, post, public_key)
from edgehub.central import digest, now, stamp


def make_link(client, site, services):
    return post(client, f"/api/admin/sites/{site['id']}/install-link", {"services": [s["id"] for s in services]})


def relay(gateway):
    return {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer " + gateway["token"]}


def payload(token, key=None, hostname="CAIXA-IGUAL"):
    return {"kind": "agent", "token": token, "public_key": key or public_key(), "hostname": hostname, "transport": "ssh-policy-v1"}


def setup(client):
    site = new_site(client)
    service = new_service(client, site)
    extra = new_service(client, site, "SSH administração", port=22)
    gateway = gateway_enroll(client, site)
    link = make_link(client, site, [service])
    token = link["url"].rsplit("/", 1)[-1]
    return site, service, extra, gateway, link, token


def test_firewall_device_capacity_rolls_back_reusable_enrollment(lab):
    client, repository, _ = lab
    site, service, _, gateway, _, token = setup(client)
    existing_key = public_key()
    def fill(state):
        for index in range(4096):
            identity = f"dev_existing_{index}"
            state["devices"][identity] = {"id": identity, "site_id": site["id"],
                "name": identity, "services": [service["id"]], "public_key": existing_key,
                "revoked": False, "last_seen": "0001-01-01T00:00:00Z", "status": "cadastrado"}
    repository.transaction(fill)
    before = repository.read()
    result = client.post("/api/enroll", json=payload(token), headers=relay(gateway))
    assert result.status_code == 409 and "capacidade" in result.text
    assert repository.read() == before


@pytest.mark.parametrize("legacy", [False, True])
def test_firewall_policy_size_rolls_back_ticket_identity_and_counter(lab, monkeypatch, legacy):
    import edgehub.central as central
    client, repository, _ = lab
    site, service, _, gateway, _, token = setup(client)
    if legacy:
        device = new_device(client, site, service)
        token = post(client, f"/api/admin/devices/{device['id']}/bootstrap", {})["token"]
    before = repository.read()
    monkeypatch.setattr(central, "MAX_GATEWAY_POLICY_BYTES", 1)
    data = payload(token)
    result = client.post("/api/enroll", json=data, headers=relay(gateway))
    assert result.status_code == 409 and "capacidade" in result.text
    assert repository.read() == before
    # The same installer/key remains usable after capacity becomes available.
    monkeypatch.setattr(central, "MAX_GATEWAY_POLICY_BYTES", 4 << 20)
    result = client.post("/api/enroll", json=data, headers=relay(gateway))
    assert result.status_code == 200, result.text


def test_link_is_site_bound_secret_free_projection_and_survives_legacy_pruning(lab):
    client, repository, _ = lab
    site, service, _, gateway, link, token = setup(client)
    assert link["url"].startswith("https://vpn.example:2222/install/windows/")
    assert link["id"].startswith("lnk_")
    assert link["services"] == [service["id"]]
    assert link["expires_at"] is None and link["installation_count"] == 0
    assert repository.read()["devices"] == {}, "A link must not pre-register a terminal"
    ticket = repository.read()["tickets"][digest(token)]
    assert ticket["kind"] == "agent-link" and ticket["object_id"] == site["id"]
    assert ticket["expires"] is None and ticket["used_count"] == 0
    assert token not in json.dumps(repository.read())
    state_response = client.get("/api/admin/state", auth=AUTH["auth"])
    view = state_response.json()["sites"][site["id"]]["installation_link"]
    assert view == {key: value for key, value in link.items() if key != "url"}
    assert token not in state_response.text and digest(token) not in state_response.text
    assert "hash" not in view and "url" not in view
    # Generating an unrelated old-style one-use enrollment must keep an
    # indefinite customer link, including the tolerated blank expiry encoding.
    repository.transaction(lambda state: state["tickets"][digest(token)].update(expires=""))
    device = new_device(client, site, service)
    post(client, f"/api/admin/devices/{device['id']}/bootstrap", {})
    assert digest(token) in repository.read()["tickets"]
    assert client.get(f"/install/windows/{token}", headers=relay(gateway)).status_code == 200


def test_same_installer_creates_many_unique_terminals_with_same_hostname(lab):
    client, repository, _ = lab
    site, service, _, gateway, link, token = setup(client)
    headers = relay(gateway)
    page = client.get(f"/install/windows/{token}", headers=headers)
    assert page.status_code == 200
    assert "vários computadores" in page.text and "Válido até ser revogado" in page.text
    assert service["name"] in page.text and "SSH administração" not in page.text
    binary = client.get(f"/install/windows/{token}/installer.exe", headers=headers)
    assert binary.status_code == 200
    size = struct.unpack("<Q", binary.content[-16:-8])[0]
    bundle = json.loads(binary.content[-size-16:-16])
    assert bundle["kind"] == "agent" and bundle["token"] == token
    requests = [payload(bundle["token"]) for _ in range(10)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda data: client.post("/api/enroll", json=data, headers=headers), requests))
    assert all(result.status_code == 200 for result in results), [result.text for result in results]
    ids = [result.json()["id"] for result in results]
    runtime_tokens = [result.json()["token"] for result in results]
    assert len(set(ids)) == len(set(runtime_tokens)) == 10
    state = repository.read()
    assert len(state["devices"]) == 10
    assert state["tickets"][digest(token)]["used_count"] == 10
    assert all(device["hostname"] == "CAIXA-IGUAL" and device["name"] == "CAIXA-IGUAL" and device["services"] == [service["id"]] for device in state["devices"].values())
    view = client.get("/api/admin/state", auth=AUTH["auth"]).json()
    assert len(view["devices"]) == 10
    assert all(device["public_key"] and device["hostname"] == "CAIXA-IGUAL" for device in view["devices"].values())
    assert view["sites"][site["id"]]["installation_link"]["installation_count"] == 10
    assert client.get(f"/install/windows/{token}/installer.exe", headers=headers).status_code == 200


def test_wrong_firewall_or_direct_central_cannot_use_reusable_link(lab):
    client, repository, _ = lab
    _, _, _, gateway, _, token = setup(client)
    other = new_site(client, "Other", "other.example:2222")
    other_gateway = gateway_enroll(client, other)
    before = repository.read()
    for headers in ({}, relay(other_gateway), {"X-EdgeHub-Gateway": "1", "Authorization": "Bearer invalid"}):
        assert client.get(f"/install/windows/{token}", headers=headers).status_code == 403
        assert client.get(f"/install/windows/{token}/installer.exe", headers=headers).status_code == 403
        assert client.post("/api/enroll", json=payload(token), headers=headers).status_code == 403
    assert repository.read() == before
    assert client.post("/api/enroll", json=payload(token), headers=relay(gateway)).status_code == 200


def test_replayed_key_is_rejected_even_after_revocation_and_comment_changes(lab):
    client, repository, _ = lab
    _, _, _, gateway, _, token = setup(client)
    key = public_key()
    responses = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: client.post("/api/enroll", json=payload(token, key), headers=relay(gateway)), range(4)))
    assert [response.status_code for response in responses].count(200) == 1
    assert [response.status_code for response in responses].count(403) == 3
    enrolled = next(response.json() for response in responses if response.status_code == 200)
    post(client, f"/api/admin/devices/{enrolled['id']}/revoke", {})
    before = repository.read()
    changed_comment = key.strip() + " same-public-key-new-comment\n"
    assert client.post("/api/enroll", json=payload(token, changed_comment), headers=relay(gateway)).status_code == 403
    assert repository.read() == before
    assert before["tickets"][digest(token)]["used_count"] == 1


def test_rotating_or_revoking_link_does_not_revoke_installed_devices(lab):
    client, repository, _ = lab
    site, first, second, gateway, original, token = setup(client)
    first_installed = client.post("/api/enroll", json=payload(token), headers=relay(gateway)).json()
    rotated = make_link(client, site, [second])
    rotated_token = rotated["url"].rsplit("/", 1)[-1]
    assert rotated["id"] != original["id"] and rotated_token != token
    assert rotated["installation_count"] == 0
    assert client.get(f"/install/windows/{token}", headers=relay(gateway)).status_code == 403
    assert client.post("/api/enroll", json=payload(token), headers=relay(gateway)).status_code == 403
    installed = client.post("/api/enroll", json=payload(rotated_token), headers=relay(gateway))
    assert installed.status_code == 200
    state = repository.read()
    assert state["devices"][first_installed["id"]]["services"] == [first["id"]]
    assert state["devices"][installed.json()["id"]]["services"] == [second["id"]]
    assert len([ticket for ticket in state["tickets"].values() if ticket["kind"] == "agent-link"]) == 1
    before_devices = copy.deepcopy(state["devices"])
    url = f"/api/admin/sites/{site['id']}/install-link"
    assert client.delete(url, **AUTH).status_code == 200
    assert client.delete(url, **AUTH).status_code == 200
    assert repository.read()["devices"] == before_devices
    assert client.get(f"/install/windows/{rotated_token}/installer.exe", headers=relay(gateway)).status_code == 403
    assert client.post("/api/enroll", json=payload(rotated_token), headers=relay(gateway)).status_code == 403
    assert client.get("/api/admin/state", auth=AUTH["auth"]).json()["sites"][site["id"]]["installation_link"] is None


def test_service_and_client_deletion_prunes_and_invalidates_links(lab):
    client, repository, _ = lab
    site, first, second, gateway, _, _ = setup(client)
    both = make_link(client, site, [first, second])
    token = both["url"].rsplit("/", 1)[-1]
    other = new_site(client, "Other", "other.example:2222")
    other_service = new_service(client, other)
    other_link = make_link(client, other, [other_service])
    other_hash = digest(other_link["url"].rsplit("/", 1)[-1])
    assert client.delete(f"/api/admin/sites/{site['id']}/services/{first['id']}", **AUTH).status_code == 200
    assert repository.read()["tickets"][digest(token)]["services"] == [second["id"]]
    assert client.post("/api/enroll", json=payload(token), headers=relay(gateway)).status_code == 200
    assert client.delete(f"/api/admin/sites/{site['id']}/services/{second['id']}", **AUTH).status_code == 200
    assert digest(token) not in repository.read()["tickets"]
    assert client.get(f"/install/windows/{token}", headers=relay(gateway)).status_code == 403
    assert other_hash in repository.read()["tickets"]
    assert client.delete(f"/api/admin/sites/{other['id']}", **AUTH).status_code == 200
    assert other_hash not in repository.read()["tickets"]


def test_permissions_authentication_and_body_validation_are_not_bypassed(lab):
    client, repository, _ = lab
    site, first, _, _, _, token = setup(client)
    other = new_site(client, "Other", "other.example:2222")
    foreign = new_service(client, other)
    url = f"/api/admin/sites/{site['id']}/install-link"
    before = repository.read()
    assert client.post(url, json={"services": [first["id"]]}).status_code == 401
    assert client.post(url, json={"services": [first["id"]]}, auth=AUTH["auth"]).status_code == 403
    assert client.delete(url, auth=AUTH["auth"]).status_code == 403
    for data in ({"services": []}, {"services": [foreign["id"]]}, {"services": [first["id"], first["id"]]}, {"services": [first["id"]], "expires": None}):
        assert client.post(url, json=data, **AUTH).status_code == 400
    assert client.request("DELETE", url, json={"unexpected": True}, **AUTH).status_code == 400
    assert repository.read() == before
    assert digest(token) in before["tickets"]


def test_legacy_single_use_enrollment_is_preserved_and_cannot_replay_key(lab):
    client, repository, _ = lab
    site, service, _, gateway, _, token = setup(client)
    legacy = new_device(client, site, service)
    legacy_result, bundle = agent_enroll(client, legacy, proxy=gateway)
    assert legacy_result.status_code == 200
    registered_key = repository.read()["devices"][legacy["id"]]["public_key"]
    before = repository.read()
    assert client.post("/api/enroll", json=payload(token, registered_key), headers=relay(gateway)).status_code == 403
    assert client.post("/api/enroll", json=payload(bundle["token"]), headers=relay(gateway)).status_code == 403
    assert repository.read() == before


def test_enrollment_also_reserves_space_for_persistent_firewall_cache(lab, monkeypatch):
    import edgehub.central as central_module
    client, repository, _ = lab
    _, _, _, gateway, _, token = setup(client)
    original_snapshot = central_module.desired_snapshot

    def near_network_limit(state, site):
        snapshot = original_snapshot(state, site)
        encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
        # The network body fits, but the persistent envelope would not.
        monkeypatch.setattr(central_module, "MAX_GATEWAY_POLICY_BYTES", len(encoded) + 1)
        return snapshot

    monkeypatch.setattr(central_module, "desired_snapshot", near_network_limit)
    before = repository.read()
    response = client.post("/api/enroll", json=payload(token), headers=relay(gateway))
    assert response.status_code == 409
    assert repository.read() == before


def test_expired_link_is_not_exposed_and_does_not_enroll(lab):
    client, repository, _ = lab
    site, _, _, gateway, _, token = setup(client)
    repository.transaction(lambda state: state["tickets"][digest(token)].update(expires=stamp(now() - timedelta(seconds=1))))
    before = repository.read()
    assert client.get(f"/install/windows/{token}", headers=relay(gateway)).status_code == 403
    assert client.post("/api/enroll", json=payload(token), headers=relay(gateway)).status_code == 403
    assert repository.read() == before
    assert client.get("/api/admin/state", auth=AUTH["auth"]).json()["sites"][site["id"]]["installation_link"] is None
