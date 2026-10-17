"""pfSense runtime: one public TCP listener, SSH and enrollment HTTPS.

No terminal calls the central directly. Only this process synchronizes policy
and descriptive telemetry. Access survives a management outage using a cached
policy tied to the gateway ID and SSH host key.
"""
from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import unicodedata

import aiohttp
import asyncssh
from asyncssh.misc import map_handler_name

from .gateway_policy import empty_snapshot, endpoint_parts, load_policy, store_policy, validate_snapshot, wire_json
from .gateway_portal import GatewayPortal, TrackedHTTP, bounded_read, private_client_context, valid_https_origin
from .central_tls import select_tls_context
from . import __version__ as VERSION

LOG = logging.getLogger(__name__)
POLICY_REQUEST = "policy-v1@o3cloudcentral"
IDENTITY_REQUEST = "identity-v1@o3cloudcentral"
CONNECTION_LIMIT, CLASSIFICATION_LIMIT, TLS_LIMIT = 288, 32, 32


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_identity(payload: bytes) -> dict | None:
    if not 0 < len(payload) <= 1024:
        return None
    try:
        info = json.loads(payload)
        if not isinstance(info, dict) or set(info) - {"hostname", "local_ip", "agent_version", "os"}:
            return None
        if any(not isinstance(value, str) for value in info.values()):
            return None
        hostname = info.get("hostname", "")
        if len(hostname.encode("utf-8")) > 253 or any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in hostname):
            return None
        hostname = hostname.strip()
        if any(c.isspace() for c in hostname):
            return None
        result = {}
        if hostname:
            result["hostname"] = hostname
        local = info.get("local_ip", "").strip()
        if local:
            address = ipaddress.ip_address(local)
            if getattr(address, "scope_id", None):
                return None
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
                return None
            result["local_ip"] = str(address)
        version = info.get("agent_version", "")
        system = info.get("os", "")
        if len(version) > 64 or len(system) > 32 or not re.fullmatch(r"[A-Za-z0-9._+\-]*", version, re.ASCII) or not re.fullmatch(r"[a-z0-9]*", system, re.ASCII):
            return None
        if version:
            result["agent_version"] = version
        if system:
            result["os"] = system
        return result or None
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None


@dataclass
class ActiveTerminal:
    device_id: str
    signature: bytes
    identity: dict = field(default_factory=dict)
    identity_seen: float = 0


class Gateway:
    def __init__(self, config: dict, cache_path: str):
        if config.get("kind") != "gateway" or not valid_https_origin(config.get("url", "")):
            raise ValueError("configuração não é de um pfSense")
        self.config = copy.deepcopy(config)
        self.cache_path = cache_path
        self.key = asyncssh.import_private_key(config["private_key"])
        # Go ssh.MarshalAuthorizedKey includes a newline and has no comment.
        public = self.key.export_public_key("openssh").decode().split()
        self.host_key = " ".join(public[:2]) + "\n"
        self.snapshot = empty_snapshot()
        self.sessions: dict[asyncssh.SSHServerConnection, ActiveTerminal] = {}
        self.health: list[dict] = []
        self.health_offset = 0
        if cache_path:
            try:
                self.snapshot = load_policy(cache_path, config, self.host_key)
                LOG.info("permissões locais restauradas; operação independente da central")
            except FileNotFoundError:
                pass
        self.client: aiohttp.ClientSession | None = None
        self.portal: GatewayPortal | None = None
        self.connections = self.classifying = self.tls_connections = 0
        self.tasks: set[asyncio.Task] = set()
        self.listener: socket.socket | None = None

    def device(self, device_id: str) -> dict | None:
        return next((d for d in self.snapshot.get("devices") or [] if d["id"] == device_id), None)

    @staticmethod
    def signature(device: dict) -> bytes:
        # Dictionaries only serve change detection here, never revision hashing.
        return json.dumps(device, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    def apply(self, snapshot: dict):
        self.snapshot = copy.deepcopy(snapshot)
        for connection, active in list(self.sessions.items()):
            device = self.device(active.device_id)
            if not device or self.signature(device) != active.signature:
                connection.close()

    def allowed(self, device_id: str, key: asyncssh.SSHKey) -> bool:
        device = self.device(device_id)
        if not device:
            return False
        try:
            return asyncssh.import_public_key(device["public_key"]) == key
        except (ValueError, asyncssh.KeyImportError):
            return False

    def target_allowed(self, device_id: str, host: str, port: int) -> bool:
        device = self.device(device_id)
        return bool(device and any(s["target"] == host and s["port"] == port for s in device.get("services") or []))

    def policy(self, device_id: str) -> dict | None:
        device = self.device(device_id)
        if not device:
            return None
        return {"control_version": 1, "endpoint": self.snapshot.get("endpoint", ""), "host_key": self.host_key,
                "services": copy.deepcopy(device.get("services") or []), "lease_seconds": 0}

    def record_identity(self, connection, payload: bytes) -> bool:
        identity = normalize_identity(payload)
        active = self.sessions.get(connection)
        if identity is None or active is None:
            return False
        device = self.device(active.device_id)
        if not device or self.signature(device) != active.signature:
            return False
        active.identity.update(identity)
        active.identity_seen = time.monotonic()
        return True

    def report(self) -> dict:
        sessions, identities, seen = {}, {}, {}
        for active in self.sessions.values():
            sessions[active.device_id] = sessions.get(active.device_id, 0) + 1
            if active.identity_seen > seen.get(active.device_id, 0):
                identities[active.device_id] = active.identity
                seen[active.device_id] = active.identity_seen
        report = {"sessions": sessions, "services": [], "version": VERSION,
                  "terminals": {}, "policy_revision": self.snapshot.get("revision", "")}
        # All management bodies, including metadata, stay below central's
        # 128 KiB decoder limit. Very large service lists rotate through syncs.
        used = len(wire_json(report))
        health = self.health[self.health_offset:] + self.health[:self.health_offset]
        for item in health:
            size = len(wire_json(item)) + bool(report["services"])
            if used + size > 96 << 10:
                break
            report["services"].append(item)
            used += size
        if self.health:
            self.health_offset = (self.health_offset + len(report["services"])) % len(self.health)
        bounded, identity_used = {}, 2
        for device_id in sorted(identities):
            size = len(wire_json(device_id)) + 1 + len(wire_json(identities[device_id])) + bool(bounded)
            if identity_used + size <= 48 << 10 and used + size <= (128 << 10) - 1024:
                bounded[device_id] = identities[device_id]
                used += size
                identity_used += size
        report["terminals"] = bounded
        return report

    async def sync(self):
        assert self.client
        try:
            async with self.client.post(self.config["url"].rstrip("/") + "/api/gateway/sync",
                                        data=wire_json(self.report()),
                                        headers={"Authorization": "Bearer " + self.config["token"], "Content-Type": "application/json"},
                                        allow_redirects=False) as response:
                if response.status == 403:
                    revoked = empty_snapshot()
                    try:
                        await asyncio.to_thread(store_policy, self.cache_path, self.config, self.host_key, revoked)
                    except OSError:
                        if self.cache_path:
                            try:
                                os.unlink(self.cache_path)
                            except OSError:
                                LOG.error("cache de permissões não pôde ser invalidado")
                    self.apply(revoked)
                    return
                if response.status != 200:
                    raise ValueError("sincronização HTTP %s" % response.status)
                raw = await bounded_read(response.content, 4 << 20)
                snapshot = json.loads(raw)
                validate_snapshot(snapshot)
                if self.snapshot.get("revision") != snapshot["revision"]:
                    # Never authorize a change which cannot survive a restart.
                    await asyncio.to_thread(store_policy, self.cache_path, self.config, self.host_key, snapshot)
                    self.apply(snapshot)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError, asyncssh.KeyImportError):
            LOG.warning("central indisponível ou política inválida; mantendo permissões locais")

    async def probe(self):
        services = list(self.snapshot.get("services") or [])
        semaphore = asyncio.Semaphore(8)

        async def one(service):
            async with semaphore:
                try:
                    _, writer = await asyncio.wait_for(asyncio.open_connection(service["target"], service["port"]), 1)
                    writer.close()
                    await writer.wait_closed()
                    reachable = True
                except (OSError, asyncio.TimeoutError):
                    reachable = False
                return {"id": service["id"], "reachable": reachable, "checked_at": utc_now()}

        health = await asyncio.gather(*(one(service) for service in services))
        if services == list(self.snapshot.get("services") or []):
            self.health = health

    async def periodic(self, stop: asyncio.Event, interval: float, action):
        while not stop.is_set():
            await action()
            try:
                await asyncio.wait_for(stop.wait(), interval)
            except asyncio.TimeoutError:
                pass

    async def classify(self, raw: socket.socket) -> str:
        deadline = asyncio.get_running_loop().time() + 0.350
        while True:
            try:
                prefix = raw.recv(4, socket.MSG_PEEK)
                if not prefix:
                    raise ConnectionError("conexão encerrada")
                if prefix[0] == 0x16:
                    return "tls"
                if not b"SSH-".startswith(prefix):
                    raise ConnectionError("protocolo não autorizado")
                if len(prefix) == 4:
                    return "ssh"
            except BlockingIOError:
                prefix = b""
            if asyncio.get_running_loop().time() >= deadline:
                if not prefix:
                    return "ssh"  # server-first presence probes get a banner
                raise ConnectionError("identificação SSH incompleta")
            await asyncio.sleep(0.01)

    async def serve_socket(self, raw: socket.socket):
        tls = False
        classifying = True
        connection = None
        transport = None
        try:
            protocol = await self.classify(raw)
            self.classifying -= 1
            classifying = False
            if protocol == "tls":
                if not self.portal or self.tls_connections >= TLS_LIMIT:
                    return
                self.tls_connections += 1
                tls = True
                loop = asyncio.get_running_loop()
                closed = loop.create_future()
                assert self.portal.runner and self.portal.runner.server
                tls_context = await select_tls_context(raw, self.portal.tls_contexts)
                transport, _ = await loop.connect_accepted_socket(
                    lambda: TrackedHTTP(self.portal.runner.server(), closed), raw,
                    ssl=tls_context, ssl_handshake_timeout=5, ssl_shutdown_timeout=2)
                await closed
            else:
                owner = GatewaySSH(self)
                connection = await asyncio.wait_for(asyncssh.connect_reverse(
                    sock=raw, config=None, server_factory=lambda: owner,
                    server_host_keys=[self.key], server_version="O3CloudCentral", login_timeout=10,
                    connect_timeout=10, password_auth=False, kbdint_auth=False,
                    host_based_auth=False, public_key_auth=True, gss_auth=False, gss_kex=False,
                    allow_pty=False, agent_forwarding=False, x11_forwarding=False,
                    allow_scp=False, sftp_factory=None, line_editor=False,
                    keepalive_interval=15, keepalive_count_max=3), 11)
                await connection.wait_closed()
        except (OSError, ConnectionError, asyncio.TimeoutError, asyncssh.Error, ValueError):
            pass
        finally:
            if classifying:
                self.classifying -= 1
            if tls:
                self.tls_connections -= 1
            self.connections -= 1
            if connection:
                connection.close()
                await connection.wait_closed()
            if transport:
                transport.close()
            raw.close()

    async def run(self, stop: asyncio.Event):
        host, port = endpoint_parts(self.config.get("listen") or "0.0.0.0:2222")
        ipaddress.ip_address(host)
        self.client = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=private_client_context(self.config["ca"]), limit=8),
            timeout=aiohttp.ClientTimeout(total=15, connect=5), trust_env=False)
        try:
            try:
                self.portal = GatewayPortal(self.config)
                await self.portal.setup()
            except (ValueError, KeyError, OSError, ssl.SSLError) as error:
                LOG.warning("portal de instalação indisponível; SSH continua disponível: %s", type(error).__name__)
                if self.portal:
                    await self.portal.close()
                self.portal = None
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            self.listener = socket.socket(family, socket.SOCK_STREAM)
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((host, port))
            self.listener.listen(128)
            self.listener.setblocking(False)
            background = [asyncio.create_task(self.periodic(stop, 5, self.sync)),
                          asyncio.create_task(self.periodic(stop, 15, self.probe))]
            accept = asyncio.create_task(self.accept_loop(stop))
            stopped = asyncio.create_task(stop.wait())
            try:
                await asyncio.wait((accept, stopped), return_when=asyncio.FIRST_COMPLETED)
                if accept.done():
                    await accept
            finally:
                for task in (accept, stopped, *background):
                    task.cancel()
                await asyncio.gather(accept, stopped, *background, return_exceptions=True)
        finally:
            if self.listener:
                self.listener.close()
            for task in list(self.tasks):
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
            if self.portal:
                await self.portal.close()
            await self.client.close()

    async def accept_loop(self, stop):
        loop = asyncio.get_running_loop()
        while not stop.is_set():
            raw, _ = await loop.sock_accept(self.listener)
            if self.connections >= CONNECTION_LIMIT or self.classifying >= CLASSIFICATION_LIMIT:
                raw.close()
                continue
            raw.setblocking(False)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.connections += 1
            self.classifying += 1
            task = asyncio.create_task(self.serve_socket(raw))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)


class GatewaySSH(asyncssh.SSHServer):
    def __init__(self, gateway: Gateway):
        self.gateway = gateway
        self.connection = None
        self.username = ""
        self.channels = 0
        self.auth_attempts = 0
        self.auth_key = None

    def connection_made(self, connection):
        self.connection = connection
        # AsyncSSH 2.24.1's request dispatcher has no public extension hook.
        # Keep the two versioned hooks isolated and covered by Go interop tests.
        for name, handler in ((POLICY_REQUEST, self.policy_request), (IDENTITY_REQUEST, self.identity_request),
                              ("keepalive@o3cloudcentral", self.keepalive_request)):
            setattr(connection, "_process_" + map_handler_name(name) + "_global_request", handler)

    def connection_lost(self, exc):
        self.gateway.sessions.pop(self.connection, None)

    def begin_auth(self, username):
        self.username = username
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        self.auth_attempts += 1
        if self.auth_attempts > 4:
            self.connection.close()
            return False
        allowed = self.gateway.allowed(username, key)
        if allowed:
            self.auth_key = key
        return allowed

    def auth_completed(self):
        device = self.gateway.device(self.username)
        count = sum(active.device_id == self.username for active in self.gateway.sessions.values())
        if not device or self.auth_key is None or not self.gateway.allowed(self.username, self.auth_key) or len(self.gateway.sessions) >= 256 or count >= 4:
            self.connection.close()
            return
        self.gateway.sessions[self.connection] = ActiveTerminal(self.username, self.gateway.signature(device))

    def policy_request(self, packet):
        payload = packet.get_remaining_payload()
        policy = self.gateway.policy(self.username) if not payload and self.connection in self.gateway.sessions else None
        self.connection._report_global_response(wire_json(policy) if policy else False)

    def identity_request(self, packet):
        self.connection._report_global_response(self.gateway.record_identity(self.connection, packet.get_remaining_payload()))

    def keepalive_request(self, packet):
        packet.check_end()
        self.connection._report_global_response(True)

    def session_requested(self):
        return False

    def server_requested(self, listen_host, listen_port):
        return False

    def unix_connection_requested(self, *args):
        return False

    def unix_server_requested(self, *args):
        return False

    def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
        if self.connection not in self.gateway.sessions or not self.gateway.target_allowed(self.username, dest_host, dest_port):
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_ADMINISTRATIVELY_PROHIBITED, "destino não autorizado")
        if self.channels >= 32:
            raise asyncssh.ChannelOpenError(asyncssh.OPEN_RESOURCE_SHORTAGE, "limite de conexões")
        self.channels += 1

        async def relay(reader, writer):
            upstream = None
            try:
                if not self.gateway.target_allowed(self.username, dest_host, dest_port):
                    return
                upstream_reader, upstream = await asyncio.wait_for(asyncio.open_connection(dest_host, dest_port), 5)

                async def copy_stream(source, target):
                    while chunk := await source.read(64 << 10):
                        target.write(chunk)
                        await target.drain()
                    if target.can_write_eof():
                        target.write_eof()

                await asyncio.gather(copy_stream(reader, upstream), copy_stream(upstream_reader, writer))
            except (OSError, asyncio.TimeoutError, asyncssh.Error):
                pass
            finally:
                self.channels -= 1
                writer.close()
                if upstream:
                    upstream.close()
                    await upstream.wait_closed()
        return relay


async def run_gateway(config: dict, cache_path: str, stop: asyncio.Event) -> None:
    await Gateway(config, cache_path).run(stop)
