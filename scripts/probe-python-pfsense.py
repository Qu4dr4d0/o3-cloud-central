#!/usr/bin/env python3
"""Ephemeral native gateway functional test. Never installs a product/service.

Run using the private bundle's Python, PYTHONHOME, LD_LIBRARY_PATH, PYTHONPATH
and O3CLOUDCENTRAL_RESOURCE_ROOT. All sockets bind 127.0.0.1 with kernel-chosen ports;
all configuration/keys/policy live in one private temporary directory.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import logging
from pathlib import Path
import socket
import shutil
import ssl
import sys
import tempfile

import aiohttp
from aiohttp import web
import asyncssh
from cryptography import x509
import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from asyncssh.constants import MSG_REQUEST_SUCCESS

from o3cloudcentral.gateway import Gateway
from o3cloudcentral.gateway_policy import snapshot_revision, store_policy
from o3cloudcentral.gateway_portal import private_client_context
from o3cloudcentral.agent import PinnedClient
from o3cloudcentral import __version__


def available_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def certificate_fixture(directory):
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral Native Probe CA")])
    ca = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256())
    private = ec.generate_private_key(ec.SECP256R1())
    leaf = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral Native Probe Server")])).issuer_name(name).public_key(private.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False).sign(key, hashes.SHA256())
    old_key = ed25519.Ed25519PrivateKey.generate()
    old_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral Legacy Probe CA")])
    old_ca = x509.CertificateBuilder().subject_name(old_subject).issuer_name(old_subject).public_key(old_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(old_key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(old_key.public_key()), critical=False).sign(old_key, None)
    bridge = x509.CertificateBuilder().subject_name(name).issuer_name(old_subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(old_key.public_key()), critical=False).sign(old_key, None)
    cert = leaf.public_bytes(serialization.Encoding.PEM).decode() + bridge.public_bytes(serialization.Encoding.PEM).decode()
    secret = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    cp, kp = directory / "server.crt", directory / "server.key"
    cp.write_text(cert)
    kp.write_text(secret)
    kp.chmod(0o600)
    (directory / "modern-ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "legacy-ca.crt").write_bytes(old_ca.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cp, kp)
    return ca.public_bytes(serialization.Encoding.PEM).decode() + old_ca.public_bytes(serialization.Encoding.PEM).decode(), cert, secret, context


async def functional_probe(directory):
    ca, certificate, private, ssl_context = certificate_fixture(directory)
    gateway_port, central_port = available_port(), available_port()
    reports = []
    authorized = False
    snapshot = {}

    async def echo(reader, writer):
        try:
            while chunk := await reader.read(8192):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
    target_port = echo_server.sockets[0].getsockname()[1]
    service = {"id": "native-echo", "name": "Ephemeral echo", "target": "127.0.0.1", "port": target_port, "local_port": 18080, "protocol": "TCP", "type": "TCP"}
    device_key = asyncssh.generate_private_key("ssh-ed25519")
    gateway_key = asyncssh.generate_private_key("ssh-ed25519")
    snapshot.update(autonomous=True, endpoint=f"127.0.0.1:{gateway_port}", devices=[{"id": "native-terminal", "public_key": device_key.export_public_key().decode(), "services": [service]}], services=[service], lease_seconds=300)
    snapshot["revision"] = snapshot_revision(snapshot)

    async def central(request):
        assert request.headers.get("Authorization") == "Bearer ephemeral-gateway-token"
        if request.path == "/api/gateway/sync":
            reports.append(await request.json())
            return web.json_response(snapshot)
        assert request.headers.get("X-O3CloudCentral-Gateway") == "1"
        if request.path.startswith("/install/windows/"):
            return web.Response(text="Ephemeral installation page")
        return web.Response(status=404)

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", central)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", central_port, ssl_context=ssl_context).start()
    config = {"kind": "gateway", "id": "native-gateway", "url": f"https://127.0.0.1:{central_port}", "ca": ca,
              "token": "ephemeral-gateway-token", "private_key": gateway_key.export_private_key().decode(),
              "listen": f"127.0.0.1:{gateway_port}", "portal_url": f"https://127.0.0.1:{gateway_port}",
              "portal_listen": f"127.0.0.1:{gateway_port}", "portal_cert": certificate, "portal_key": private}
    gateway = Gateway(config, str(directory / "policy.json"))
    store_policy(gateway.cache_path, config, gateway.host_key, snapshot)
    gateway.apply(snapshot)
    stop = asyncio.Event()
    task = asyncio.create_task(gateway.run(stop))
    try:
        for _ in range(300):
            if task.done():
                await task
            if gateway.listener:
                break
            await asyncio.sleep(0.01)
        assert gateway.listener and gateway.portal
        # A server-first SSH presence probe must receive the normal banner.
        reader, writer = await asyncio.open_connection("127.0.0.1", gateway_port)
        assert (await asyncio.wait_for(reader.readline(), 3)).startswith(b"SSH-2.0-O3CloudCentral")
        writer.close()
        await writer.wait_closed()
        async with asyncssh.connect("127.0.0.1", gateway_port, username="native-terminal",
                client_keys=[device_key], known_hosts=(), client_factory=lambda: PinnedClient(gateway.host_key),
                agent_path=None, config=None, preferred_auth=["publickey"], encoding=None) as connection:
            success, packet = await connection._make_global_request(b"policy-v1@o3cloudcentral")
            assert success == MSG_REQUEST_SUCCESS
            policy = json.loads(packet.get_remaining_payload())
            assert policy["control_version"] == 1 and policy["services"][0]["id"] == "native-echo"
            identity = {"hostname": "NATIVE-EPHEMERAL", "local_ip": "192.168.245.10", "agent_version": __version__, "os": "windows"}
            success, _ = await connection._make_global_request(b"identity-v1@o3cloudcentral", json.dumps(identity).encode())
            assert success == MSG_REQUEST_SUCCESS
            remote_reader, remote_writer = await connection.open_connection("127.0.0.1", target_port)
            remote_writer.write(b"native-one-port")
            assert await asyncio.wait_for(remote_reader.readexactly(15), 3) == b"native-one-port"
            remote_writer.close()
            await remote_writer.wait_closed()
            try:
                await connection.open_connection("127.0.0.1", target_port + 1)
            except asyncssh.ChannelOpenError:
                denied = True
            else:
                raise AssertionError("unauthorized destination accepted")
            try:
                await connection.run("id")
            except asyncssh.ChannelOpenError:
                shell_denied = True
            else:
                raise AssertionError("shell accepted")
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=private_client_context(ca)), trust_env=False) as client:
                base = f"https://127.0.0.1:{gateway_port}"
                for path in ("/install/windows/" + "A" * 43, "/install/windows.css", "/favicon.ico", "/brand/logo.png"):
                    async with client.get(base + path) as response:
                        assert response.status == 200 and await response.read()
                async with client.get(base + "/api/admin/sites") as response:
                    assert response.status == 404
            # An old Go agent trusts only the Ed25519 root, so it needs the
            # compatibility bridge. Schannel needs the short ECDSA chain.
            legacy = ssl.create_default_context(cafile=str(directory / "legacy-ca.crt"))
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=legacy), trust_env=False) as client:
                async with client.get(f"https://127.0.0.1:{gateway_port}/favicon.ico") as response:
                    assert response.status == 200 and await response.read()
            schannel = False
            if shutil.which("openssl"):
                process = await asyncio.create_subprocess_exec(shutil.which("openssl"), "s_client", "-connect", f"127.0.0.1:{gateway_port}", "-CAfile", str(directory / "modern-ca.crt"), "-verify_return_error", "-verify_ip", "127.0.0.1", "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-quiet", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"), 10)
                assert process.returncode == 0 and b"200 OK" in output
                schannel = True
            await gateway.sync()
            assert reports[-1]["terminals"]["native-terminal"] == identity
        return {"status": "passed", "platform": sys.platform, "python": sys.version.split()[0],
                "asyncssh": asyncssh.__version__, "aiohttp": aiohttp.__version__, "cryptography": cryptography.__version__,
                "same_port_ssh_https": True, "pinned_host_key": True, "tcp_echo": True,
                "policy_request": True, "telemetry_via_gateway": True, "css_favicon": True,
                "legacy_ca_bridge": True, "schannel_signature_handshake": schannel,
                "unauthorized_destination_denied": denied, "shell_denied": shell_denied,
                "admin_proxy_denied": True, "product_installed": False}
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)
        echo_server.close()
        await echo_server.wait_closed()
        await runner.cleanup()


def main():
    logging.basicConfig(level=logging.ERROR)
    try:
        with tempfile.TemporaryDirectory(prefix="o3cloudcentral-native-functional-") as temporary:
            result = asyncio.run(asyncio.wait_for(functional_probe(Path(temporary)), 45))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "product_installed": False}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
