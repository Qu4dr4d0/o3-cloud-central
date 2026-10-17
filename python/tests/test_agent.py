import asyncio
import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import asyncssh
from asyncssh.misc import map_handler_name

from edgehub.agent import AgentControl, collect_identity, run_agent, split_endpoint, validate_policy


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class AgentValidationTests(unittest.TestCase):
    def test_endpoint_validation(self):
        self.assertEqual(split_endpoint("ddns.example:2222"), ("ddns.example", 2222))
        self.assertEqual(split_endpoint("[::1]:2222"), ("::1", 2222))
        for value in ("", "host", "host:0", "host:65536", "::1:2222", "host:abc"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                split_endpoint(value)

    def test_telemetry_never_fabricates_nat_address(self):
        with patch("socket.gethostname", return_value="CAIXA-01"):
            info = collect_identity(("192.168.5.22", 4000))
            self.assertEqual(info["hostname"], "CAIXA-01")
            self.assertEqual(info["local_ip"], "192.168.5.22")
            self.assertIn("agent_version", info)
            self.assertIn("os", info)
            self.assertNotIn("local_ip", collect_identity(("127.0.0.1", 1)))
        with patch("socket.gethostname", return_value="fake\nname"):
            self.assertNotIn("hostname", collect_identity())

    def test_policy_rejects_duplicate_local_port_and_wrong_identity(self):
        key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        service = {"id": "web", "target": "172.30.20.10", "port": 80, "local_port": 18080}
        policy = {"control_version": 1, "host_key": key, "endpoint": "example.test:2222", "services": [service]}
        validate_policy(policy, key)
        with self.assertRaises(ValueError):
            validate_policy(policy, other)
        policy["services"].append(dict(service, id="other"))
        with self.assertRaises(ValueError):
            validate_policy(policy, key)
        for port in (True, 22, 65536):
            policy["services"] = [dict(service, local_port=port)]
            with self.assertRaises(ValueError):
                validate_policy(policy, key)


class FixtureSSH(asyncssh.SSHServer):
    def __init__(self, fixture):
        self.fixture = fixture

    def connection_made(self, connection):
        self.connection = connection
        self.fixture.connections.add(connection)
        for name, handler in (("policy-v1@edgehub", self.policy), ("identity-v1@edgehub", self.identity), ("keepalive@edgehub", self.keepalive)):
            setattr(connection, "_process_" + map_handler_name(name) + "_global_request", handler)

    def begin_auth(self, username):
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "terminal-01" and key == self.fixture.client_key.convert_to_public()

    def policy(self, packet):
        packet.check_end()
        self.connection._report_global_response(json.dumps(self.fixture.policy).encode())

    def identity(self, packet):
        self.fixture.identities.append(json.loads(packet.get_remaining_payload()))
        self.connection._report_global_response(True)

    def keepalive(self, packet):
        packet.check_end()
        self.connection._report_global_response(True)

    def connection_requested(self, target, port, origin, origin_port):
        if target != "127.0.0.1" or port != self.fixture.upstream_port:
            return False
        return True

    def session_requested(self):
        return False


class AgentIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "config.json"
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.client_key = asyncssh.generate_private_key("ssh-ed25519")
        self.connections = set()
        self.identities = []
        async def echo(reader, writer):
            try:
                while raw := await reader.read(10000):
                    writer.write(raw)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        self.upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        self.upstream_port = self.upstream.sockets[0].getsockname()[1]
        self.server = await asyncssh.create_server(lambda: FixtureSSH(self), "127.0.0.1", 0,
            server_host_keys=[self.host_key], config=None)
        endpoint = "127.0.0.1:" + str(self.server.get_port())
        self.local_port = available_port()
        self.policy = {"control_version": 1, "endpoint": endpoint,
            "host_key": self.host_key.export_public_key().decode(), "lease_seconds": 300,
            "services": [{"id": "web", "name": "Nginx", "target": "127.0.0.1", "port": self.upstream_port, "local_port": self.local_port, "protocol": "TCP"}]}
        self.config = {"kind": "agent", "id": "terminal-01", "private_key": self.client_key.export_private_key().decode(),
            "gateway_endpoint": endpoint, "gateway_host_key": self.host_key.export_public_key().decode(),
            "url": "https://central.must-not-be-contacted.invalid:8443", "token": "never-sent", "ca": "unused"}
        self.path.write_text(json.dumps(self.config))
        self.stop = asyncio.Event()
        self.control = AgentControl()
        self.task = None

    async def asyncTearDown(self):
        self.stop.set()
        if self.task:
            await asyncio.wait_for(self.task, 4)
        for connection in self.connections:
            connection.close()
        await asyncio.gather(*(connection.wait_closed() for connection in self.connections))
        self.server.close()
        await self.server.wait_closed()
        self.upstream.close()
        await self.upstream.wait_closed()
        self.directory.cleanup()

    async def wait_state(self, state, timeout=5):
        until = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < until:
            if self.control.snapshot()["state"] == state:
                return
            await asyncio.sleep(.02)
        self.fail("Estado não atingido: " + state + ": " + str(self.control.snapshot()))

    async def roundtrip(self, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"edgehub-python")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(14), 3), b"edgehub-python")
        writer.close()
        await writer.wait_closed()

    async def test_real_ssh_forward_identity_pause_reconnect_and_boot(self):
        self.task = asyncio.create_task(run_agent(self.path, self.stop, self.control))
        await self.wait_state("conectado")
        await self.roundtrip(self.local_port)
        await asyncio.sleep(.1)
        self.assertTrue(self.identities)
        self.assertIn("hostname", self.identities[-1])
        self.assertIn("agent_version", self.identities[-1])
        # No runtime HTTP/central API can occur: its URL is intentionally invalid.
        await self.control.command("disconnect")
        self.assertTrue(self.control.snapshot()["paused"])
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", self.local_port)
        await self.control.command("connect")
        await self.wait_state("conectado")
        await self.roundtrip(self.local_port)
        for connection in tuple(self.connections):
            connection.close()
        await self.wait_state("reconectando")
        await self.wait_state("conectado")
        await self.roundtrip(self.local_port)
        await self.control.command("disconnect")
        self.stop.set()
        await self.task
        self.stop = asyncio.Event()
        # Reusing even the same controller must never persist the previous pause.
        self.task = asyncio.create_task(run_agent(self.path, self.stop, self.control))
        await self.wait_state("conectado")
        self.assertFalse(self.control.snapshot()["paused"])

    async def test_policy_change_closes_old_listener_and_rebuilds(self):
        with patch("edgehub.agent.POLICY_INTERVAL", .1):
            self.task = asyncio.create_task(run_agent(self.path, self.stop, self.control))
            await self.wait_state("conectado")
            await self.roundtrip(self.local_port)
            second = available_port()
            self.policy["services"][0]["local_port"] = second
            until = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < until:
                if (self.control.snapshot().get("services") or [{}])[0].get("local_port") == second and self.control.snapshot()["state"] == "conectado":
                    break
                await asyncio.sleep(.02)
            await self.roundtrip(second)
            with self.assertRaises(OSError):
                await asyncio.open_connection("127.0.0.1", self.local_port)

    async def test_wrong_pinned_host_key_never_binds_services(self):
        self.config["gateway_host_key"] = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
        self.path.write_text(json.dumps(self.config))
        self.task = asyncio.create_task(run_agent(self.path, self.stop, self.control))
        await self.wait_state("reconectando")
        self.assertFalse(self.identities)
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", self.local_port)
