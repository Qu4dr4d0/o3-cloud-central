"""Compatibility of a reusable central link with unchanged terminal/PF code.

The central and both customer relays use real, locally trusted TLS sockets.
Only the repository is a test double; the downloaded executable trailer, relay
and terminal enrollment function are the production implementations.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import socket
import ssl
from urllib.parse import urlsplit

from aiohttp import web
import asyncssh
import httpx
import pytest
import uvicorn

from edgehub.central import create_app
from edgehub.common import embedded_bundle, enroll
from edgehub.crypto import initialize_pki, new_gateway_portal_csr
from edgehub.gateway_portal import GatewayPortal
from test_central import AUTH, MemoryRepository


def _unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@asynccontextmanager
async def _central_server(app, folder):
    config = uvicorn.Config(app, host="127.0.0.1", port=0,
        ssl_certfile=str(folder / "server.crt"),
        ssl_keyfile=str(folder / "server.key"),
        lifespan="off", http="h11", access_log=False, log_level="error",
        timeout_graceful_shutdown=2)
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(200):
            if task.done():
                await task
            if server.started:
                break
            await asyncio.sleep(0.01)
        assert server.started
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"https://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)


@asynccontextmanager
async def _portal(config):
    portal = GatewayPortal(config)
    try:
        await portal.setup()
        await web.TCPSite(portal.runner, "127.0.0.1",
            int(urlsplit(config["portal_url"]).port),
            ssl_context=portal.ssl).start()
        yield portal
    finally:
        await portal.close()


@pytest.mark.asyncio
async def test_reusable_installer_enrolls_two_unique_terminals_via_own_pfsense(tmp_path, monkeypatch):
    import edgehub.central as central
    import edgehub.common as common

    monkeypatch.setattr(central, "check_admin_password",
        lambda hashed, password: hashed == "test-hash" and password == "fixture-password")
    initialize_pki(tmp_path, ["127.0.0.1"])
    executable = b"MZfixture-not-an-executable"
    (tmp_path / "O3CloudCentral.exe").write_bytes(executable)
    repository = MemoryRepository()
    app = create_app(repository, tmp_path, monitor=False)
    terminal_requests = []

    @app.middleware("http")
    async def observe_customer_relay(request, call_next):
        if request.url.path.startswith("/install/windows/") or request.url.path == "/api/enroll":
            terminal_requests.append((request.url.path,
                request.headers.get("x-edgehub-gateway"),
                request.headers.get("authorization")))
        return await call_next(request)

    ca = (tmp_path / "ca.crt").read_text()
    trust = ssl.create_default_context(cadata=ca)
    async with _central_server(app, tmp_path) as central_url:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
                                    base_url="https://central.example") as admin:
            async def post(path, payload):
                response = await admin.post(path, json=payload, **AUTH)
                assert response.status_code == 200, response.text
                return response.json()

            configs, sites, service = [], [], None
            for index in range(2):
                port = _unused_port()
                site = await post("/api/admin/sites", {
                    "name": f"Customer {index}", "endpoint": f"127.0.0.1:{port}"})
                sites.append(site)
                if index == 0:
                    service = await post(f"/api/admin/sites/{site['id']}/services", {
                        "name": "Internal web", "target": "172.30.20.10",
                        "port": 80, "type": "HTTP"})
                bundle = await post(f"/api/admin/sites/{site['id']}/bootstrap", {})
                key = asyncssh.generate_private_key("ssh-ed25519")
                csr, private = new_gateway_portal_csr()
                response = await admin.post("/api/enroll", json={
                    "kind": "gateway", "token": bundle["token"],
                    "public_key": key.export_public_key().decode(), "portal_csr": csr})
                assert response.status_code == 200, response.text
                enrolled = response.json()
                configs.append({"kind": "gateway", "id": site["id"],
                    "url": central_url, "token": enrolled["token"], "ca": ca,
                    "portal_url": enrolled["portal_url"],
                    "portal_listen": enrolled["portal_listen"],
                    "portal_cert": enrolled["portal_cert"], "portal_key": private})

            result = await post(f"/api/admin/sites/{sites[0]['id']}/install-link",
                                {"services": [service["id"]]})

        terminal_requests.clear()
        async with _portal(configs[0]), _portal(configs[1]):
            base = configs[0]["portal_url"].rstrip("/")
            other_base = configs[1]["portal_url"].rstrip("/")
            route = urlsplit(result["url"]).path
            assert result["url"].startswith(base + "/install/windows/")
            async with httpx.AsyncClient(verify=trust, trust_env=False) as terminal:
                page = await terminal.get(result["url"])
                assert page.status_code == 200, page.text
                download = await terminal.get(result["url"] + "/installer.exe")
                assert download.status_code == 200
                assert download.content.startswith(executable)
                installer = tmp_path / "O3CloudCentral-setup.exe"
                installer.write_bytes(download.content)
                bundle = embedded_bundle(installer)
                assert bundle["kind"] == "agent"
                assert bundle["url"] == base
                wrong_page = await terminal.get(other_base + route)
                assert wrong_page.status_code == 403
                wrong_enroll = await terminal.post(other_base + "/api/enroll", json={
                    "kind": "agent", "token": bundle["token"],
                    "public_key": asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode(),
                    "hostname": "WRONG-CUSTOMER", "transport": "ssh-policy-v1"})
                assert wrong_enroll.status_code == 403

            requested_origins = []
            api_request = common.api_request

            async def terminal_request(config, *args, **kwargs):
                requested_origins.append(config["url"])
                assert config["url"] == base
                return await api_request(config, *args, **kwargs)

            monkeypatch.setattr(common, "api_request", terminal_request)
            # Identical hostnames are valid on distinct computers; they must
            # never cause identities, keys or authorization to be shared.
            monkeypatch.setattr(common.socket, "gethostname", lambda: "SAME-HOSTNAME")
            first, second = await asyncio.gather(
                enroll(bundle, tmp_path / "terminal-one.json"),
                enroll(bundle, tmp_path / "terminal-two.json"))
            assert first["id"] != second["id"]
            assert first["private_key"] != second["private_key"]
            assert first["token"] != second["token"]
            assert requested_origins == [base, base]
            assert first["gateway_endpoint"] == sites[0]["endpoint"]
            assert second["gateway_host_key"] == first["gateway_host_key"]
            devices = repository.read()["devices"]
            assert set(devices) == {first["id"], second["id"]}
            for device in devices.values():
                assert device["site_id"] == sites[0]["id"]
                assert device["hostname"] == "SAME-HOSTNAME"
                assert device["services"] == [service["id"]]
                assert device["public_key"]
            assert {path for path, _, _ in terminal_requests} >= {
                route, route + "/installer.exe", "/api/enroll"}
            assert all(marker == "1" and authorization in {
                "Bearer " + configs[0]["token"], "Bearer " + configs[1]["token"]}
                for _, marker, authorization in terminal_requests)
