from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import socket
import shutil
import ssl
import subprocess

import aiohttp
from aiohttp import web
import asyncssh
from asyncssh.packet import String, SSHPacket
from asyncssh.constants import MSG_REQUEST_SUCCESS
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import pytest

from edgehub.gateway import Gateway, normalize_identity
from edgehub.gateway_policy import snapshot_revision, validate_snapshot, store_policy, load_policy
from edgehub.gateway_portal import portal_route, private_client_context
from test_central_tls import bridge


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificates(tmp_path):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gateway Test CA")])
    ca = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=2)).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).sign(key, hashes.SHA256())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Gateway Test Server')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1)).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), critical=False).sign(key, hashes.SHA256())
    cert = leaf.public_bytes(serialization.Encoding.PEM).decode()
    private = leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    (tmp_path / "cert.pem").write_text(cert)
    (tmp_path / "key.pem").write_text(private)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    return ca.public_bytes(serialization.Encoding.PEM).decode(), cert, private, ctx


class Lab:
    async def start(self, tmp_path):
        self.tmp = tmp_path
        self.ca, cert, private, ctx = certificates(tmp_path)
        self.gateway_port, central_port, self.target_port = free_port(), free_port(), free_port()
        self.device_key = asyncssh.generate_private_key("ssh-ed25519")
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.config = {"kind": "gateway", "id": "site-test", "url": f"https://127.0.0.1:{central_port}", "ca": self.ca, "token": "gateway-secret", "private_key": host_key.export_private_key().decode(), "listen": f"127.0.0.1:{self.gateway_port}", "portal_url": f"https://127.0.0.1:{self.gateway_port}", "portal_listen": f"127.0.0.1:{self.gateway_port}", "portal_cert": cert, "portal_key": private}
        service = {"id": "echo", "name": "Echo & <service>", "target": "127.0.0.1", "port": self.target_port, "local_port": 18080, "protocol": "TCP", "type": "TCP"}
        self.snapshot = {"autonomous": True, "endpoint": f"127.0.0.1:{self.gateway_port}", "devices": [{"id": "terminal-one", "public_key": self.device_key.export_public_key().decode(), "services": [service]}], "services": [service], "lease_seconds": 300}
        self.snapshot["revision"] = snapshot_revision(self.snapshot)
        self.requests, self.reports = [], []
        self.revoked = False
        self.central_status = 200
        self.redirect = False
        app = web.Application(client_max_size=1 << 20)
        app.router.add_route("*", "/{tail:.*}", self.central)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", central_port, ssl_context=ctx).start()
        self.echo_server = await asyncio.start_server(self.echo, "127.0.0.1", self.target_port)
        self.gateway = Gateway(self.config, str(tmp_path / "gateway-policy.json"))
        store_policy(self.gateway.cache_path, self.config, self.gateway.host_key, self.snapshot)
        self.gateway.apply(self.snapshot)
        self.stop = asyncio.Event()
        self.task = asyncio.create_task(self.gateway.run(self.stop))
        for _ in range(200):
            if self.task.done():
                await self.task
            if self.gateway.listener:
                break
            await asyncio.sleep(0.01)
        return self

    async def central(self, request):
        assert request.headers.get("Authorization") == "Bearer gateway-secret"
        self.requests.append((request.path, dict(request.headers)))
        if request.path == "/api/gateway/sync":
            self.reports.append(await request.json())
            if self.revoked:
                return web.Response(status=403)
            return web.json_response(self.snapshot, status=self.central_status)
        assert request.headers.get("X-EdgeHub-Gateway") == "1"
        if self.redirect:
            return web.Response(status=302, headers={"Location": "https://secret.private/"})
        if request.path == "/api/enroll":
            return web.json_response({"ok": True, "received": await request.json()}, headers={"Set-Cookie": "secret=value"})
        if request.path.endswith("installer.exe"):
            return web.Response(body=b"MZ" + b"x" * 100000, content_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="EdgeHub.exe"'})
        return web.Response(text="<html>Install</html>", content_type="text/html")

    async def echo(self, reader, writer):
        try:
            while chunk := await reader.read(8192):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def connect(self, key=None, username="terminal-one"):
        return await asyncssh.connect("127.0.0.1", self.gateway_port, username=username, client_keys=[key or self.device_key], known_hosts=None, config=None)

    async def close(self):
        self.stop.set()
        await asyncio.wait_for(self.task, 5)
        self.echo_server.close()
        await self.echo_server.wait_closed()
        await self.runner.cleanup()


@pytest.fixture
async def lab(tmp_path):
    instance = await Lab().start(tmp_path)
    try:
        yield instance
    finally:
        await instance.close()


@pytest.mark.asyncio
async def test_same_port_ssh_https_policy_identity_and_denials(lab):
    async with await lab.connect() as connection:
        result, packet = await connection._make_global_request("policy-v1@edgehub")
        assert result == MSG_REQUEST_SUCCESS
        policy = json.loads(packet.get_remaining_payload())
        assert policy["control_version"] == 1 and policy["services"][0]["id"] == "echo"
        identity = {"hostname": "CAIXA-02", "local_ip": "192.168.5.14", "agent_version": "0.4.0-lab", "os": "windows"}
        result, _ = await connection._make_global_request("identity-v1@edgehub", json.dumps(identity).encode())
        assert result == MSG_REQUEST_SUCCESS
        reader, writer = await connection.open_connection("127.0.0.1", lab.target_port)
        writer.write(b"hello")
        assert await reader.readexactly(5) == b"hello"
        writer.close()
        await writer.wait_closed()
        with pytest.raises(asyncssh.ChannelOpenError):
            await connection.open_connection("127.0.0.1", lab.target_port + 1)
        with pytest.raises(asyncssh.ChannelOpenError):
            await connection.run("id")
        with pytest.raises(asyncssh.ChannelListenError):
            await connection.forward_remote_port("127.0.0.1", 0, "127.0.0.1", lab.target_port)
        assert lab.gateway.report()["terminals"]["terminal-one"] == identity
        # HTTPS runs concurrently with SSH and accepts no incoming credentials.
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=private_client_context(lab.ca))) as client:
            base = f"https://127.0.0.1:{lab.gateway_port}"
            token = "A" * 43
            async with client.get(base + "/install/windows/" + token, headers={"Authorization": "Bearer stolen", "Cookie": "admin=yes", "X-Forwarded-For": "10.0.0.1"}) as response:
                assert response.status == 200 and "Install" in await response.text()
            forwarded = next(headers for path, headers in lab.requests if path.startswith("/install"))
            assert forwarded["Authorization"] == "Bearer gateway-secret"
            assert "Cookie" not in forwarded and "X-Forwarded-For" not in forwarded
            async with client.get(base + "/install/windows/" + token + "/installer.exe") as response:
                assert response.status == 200 and len(await response.read()) == 100002
            async with client.post(base + "/api/enroll", json={"token": "test"}) as response:
                assert response.status == 200 and "Set-Cookie" not in response.headers
            for asset in ("/install/windows.css", "/favicon.ico", "/brand/logo.png"):
                async with client.get(base + asset) as response:
                    assert response.status == 200 and len(await response.read()) > 100
            before = len(lab.requests)
            for path in ("/", "/api/admin/sites", "/api/gateway/sync", "/install/windows/" + token + "?x=1"):
                async with client.get(base + path) as response:
                    assert response.status == 404
            assert len(lab.requests) == before
        await lab.gateway.sync()
        assert lab.reports[-1]["terminals"]["terminal-one"]["hostname"] == "CAIXA-02"


@pytest.mark.asyncio
async def test_policy_change_revokes_existing_sessions_and_rejects_wrong_keys(lab):
    with pytest.raises(asyncssh.PermissionDenied):
        await lab.connect(asyncssh.generate_private_key("ssh-ed25519"))
    connection = await lab.connect()
    lab.snapshot["devices"] = []
    lab.snapshot["revision"] = snapshot_revision(lab.snapshot)
    await lab.gateway.sync()
    await asyncio.wait_for(connection.wait_closed(), 2)
    cached = load_policy(lab.gateway.cache_path, lab.config, lab.gateway.host_key)
    assert cached["devices"] == []


@pytest.mark.asyncio
async def test_central_failure_keeps_cache_but_explicit_403_revokes(lab):
    connection = await lab.connect()
    lab.central_status = 503
    await lab.gateway.sync()
    assert lab.gateway.device("terminal-one") is not None
    restored = Gateway(lab.config, lab.gateway.cache_path)
    assert restored.device("terminal-one") is not None
    lab.revoked = True
    await lab.gateway.sync()
    await asyncio.wait_for(connection.wait_closed(), 2)
    assert Gateway(lab.config, lab.gateway.cache_path).device("terminal-one") is None


@pytest.mark.asyncio
async def test_invalid_portal_never_disables_ssh(tmp_path):
    lab = await Lab().start(tmp_path)
    try:
        assert lab.gateway.portal
        # Cover creation-time legacy configurations, not just portal handler.
        config = dict(lab.config)
        for key in ("portal_cert", "portal_key", "portal_url", "portal_listen"):
            config.pop(key)
        config["listen"] = "127.0.0.1:" + str(free_port())
        legacy = Gateway(config, lab.gateway.cache_path)
        stop = asyncio.Event()
        task = asyncio.create_task(legacy.run(stop))
        for _ in range(100):
            if legacy.listener:
                break
            await asyncio.sleep(0.01)
        async with await asyncssh.connect("127.0.0.1", int(config["listen"].split(":")[-1]), username="terminal-one", client_keys=[lab.device_key], known_hosts=None, config=None) as connection:
            assert connection
        stop.set()
        await task
    finally:
        await lab.close()


@pytest.mark.asyncio
async def test_portal_refuses_redirect_and_oversize_request(lab):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=private_client_context(lab.ca))) as client:
        base = f"https://127.0.0.1:{lab.gateway_port}"
        lab.redirect = True
        async with client.get(base + "/install/windows/" + "A" * 43) as response:
            assert response.status == 502
            assert "secret.private" not in await response.text()
            assert "Location" not in response.headers
        async with client.post(base + "/api/enroll", data=b"x" * ((128 << 10) + 1), headers={"Content-Type": "application/json"}) as response:
            assert response.status == 413


def test_telemetry_is_descriptive_not_identity():
    assert normalize_identity(b'{"hostname":"PC","id":"other"}') is None
    assert normalize_identity(b'{"hostname":"P\\nC"}') is None
    assert normalize_identity(b'{"local_ip":"127.0.0.1"}') is None
    assert normalize_identity(b'{"hostname":"PC","local_ip":"192.168.1.2"}') == {"hostname": "PC", "local_ip": "192.168.1.2"}


def test_cache_cannot_cross_gateway_identity(tmp_path):
    config = {"id": "site-one"}
    snapshot = {"autonomous": True, "devices": [], "services": [], "lease_seconds": 300}
    snapshot["revision"] = snapshot_revision(snapshot)
    path = str(tmp_path / "policy.json")
    store_policy(path, config, "hostkey", snapshot)
    with pytest.raises(ValueError):
        load_policy(path, {"id": "site-two"}, "hostkey")
    with pytest.raises(ValueError):
        load_policy(path, config, "other-hostkey")
    damaged = copy.deepcopy(snapshot)
    damaged["devices"].append({"id": "injected"})
    with pytest.raises(ValueError):
        validate_snapshot(damaged)


def test_portal_route_exact_whitelist():
    token = "_" * 43
    assert portal_route("GET", "/install/windows/" + token) == ("/install/windows/" + token, False)
    for method, path in (("POST", "/api/admin/sites"), ("GET", "/api/enroll"), ("GET", "/install/windows/../admin"), ("GET", "/favicon.ico?v=1"), ("GET", "/%61pi/enroll"), ("GET", "/api/admin")):
        assert portal_route(method, path) is None


@pytest.mark.asyncio
async def test_python_agent_uses_only_gateway_and_reports_telemetry(lab, tmp_path):
    from edgehub.agent import run_agent, AgentControl
    # The central address is intentionally unusable to this terminal. Initial
    # enrollment is complete, so every runtime operation must use the gateway.
    local_port = free_port()
    service = lab.snapshot["devices"][0]["services"][0]
    service["local_port"] = local_port
    lab.snapshot["revision"] = snapshot_revision(lab.snapshot)
    lab.gateway.apply(lab.snapshot)
    config = {"kind": "agent", "id": "terminal-one", "url": "https://127.0.0.1:1", "ca": lab.ca,
              "token": "unused-terminal-secret", "private_key": lab.device_key.export_private_key().decode(),
              "gateway_endpoint": f"127.0.0.1:{lab.gateway_port}", "gateway_host_key": lab.gateway.host_key}
    path = tmp_path / "agent.json"
    path.write_text(json.dumps(config))
    stop, control = asyncio.Event(), AgentControl()
    task = asyncio.create_task(run_agent(str(path), stop, control))
    try:
        for _ in range(300):
            if task.done():
                await task
            if control.snapshot()["state"] == "conectado":
                break
            await asyncio.sleep(0.01)
        assert control.snapshot()["state"] == "conectado"
        reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
        writer.write(b"python-end-to-end")
        assert await asyncio.wait_for(reader.readexactly(17), 3) == b"python-end-to-end"
        writer.close()
        await writer.wait_closed()
        for _ in range(100):
            if lab.gateway.report()["terminals"]:
                break
            await asyncio.sleep(0.01)
        identity = lab.gateway.report()["terminals"]["terminal-one"]
        assert identity["hostname"] == socket.gethostname()
        from edgehub import __version__
        assert identity["agent_version"] == __version__
        await lab.gateway.sync()
        assert lab.reports[-1]["terminals"]["terminal-one"]["hostname"] == socket.gethostname()
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)


@pytest.mark.asyncio
async def test_failed_cache_write_never_authorizes_new_permissions(lab, monkeypatch):
    original = lab.gateway.snapshot["revision"]
    lab.snapshot["devices"][0]["services"].append({"id": "new", "name": "new", "target": "127.0.0.1", "port": lab.target_port + 1, "local_port": 18081})
    lab.snapshot["revision"] = snapshot_revision(lab.snapshot)
    def failed_write(*args):
        raise OSError("disk full")
    monkeypatch.setattr("edgehub.gateway.store_policy", failed_write)
    await lab.gateway.sync()
    assert lab.gateway.snapshot["revision"] == original
    assert not lab.gateway.target_allowed("terminal-one", "127.0.0.1", lab.target_port + 1)


@pytest.mark.asyncio
async def test_gateway_portal_legacy_ca_and_schannel_chain_selection(lab, bridge):
    folder, _ = bridge
    port = free_port()
    config = dict(lab.config)
    config.update(listen=f"127.0.0.1:{port}", portal_listen=f"127.0.0.1:{port}",
                  portal_url=f"https://127.0.0.1:{port}", portal_cert=(folder / "server.crt").read_text(),
                  portal_key=(folder / "server.key").read_text(),
                  ca=lab.ca + (folder / "ca.crt").read_text() + (folder / "legacy.crt").read_text())
    gateway = Gateway(config, lab.gateway.cache_path)
    stop = asyncio.Event()
    task = asyncio.create_task(gateway.run(stop))
    try:
        for _ in range(200):
            if task.done():
                await task
            if gateway.listener:
                break
            await asyncio.sleep(0.01)
        assert gateway.portal and gateway.portal.tls_contexts.full is not gateway.portal.tls_contexts.standard
        for trust in ("legacy.crt", "ca.crt"):
            context = ssl.create_default_context(cafile=str(folder / trust))
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=context)) as client:
                async with client.get(f"https://127.0.0.1:{port}/favicon.ico") as response:
                    assert response.status == 200
                    assert await response.read()
        if shutil.which("openssl"):
            process = await asyncio.create_subprocess_exec(shutil.which("openssl"), "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-CAfile", str(folder / "ca.crt"), "-verify_return_error", "-verify_hostname", "localhost", "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-quiet", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            output, error = await asyncio.wait_for(process.communicate(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"), 10)
            assert process.returncode == 0, error.decode(errors="replace")
            assert b"200 OK" in output
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)
