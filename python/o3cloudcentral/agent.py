"""Terminal data plane. Runtime communication is exclusively with its pfSense.

The three global requests intentionally preserve the Go v1 wire protocol. AsyncSSH
does not expose arbitrary client global requests as a public API; that interaction
is isolated in ``global_request`` and covered by a real SSH integration test.
"""
from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import os
import platform
import random
import socket
import time
import unicodedata
from pathlib import Path
from typing import Any

import asyncssh
from asyncssh.constants import MSG_REQUEST_SUCCESS

try:
    from . import __version__
except ImportError:
    __version__ = "0.7.0"

LOG = logging.getLogger(__name__)
MAX_POLICY = 128 << 10
POLICY_INTERVAL = 5.0
IDENTITY_INTERVAL = 10.0
REQUEST_TIMEOUT = 5.0


def split_endpoint(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or any(c.isspace() or c in "/\\@?#\x00" for c in value):
        raise ValueError("endereço do pfSense inválido")
    if value.startswith("["):
        host, separator, rest = value[1:].partition("]:")
        if not separator:
            raise ValueError("endereço IPv6 deve informar a porta")
        ipaddress.IPv6Address(host)
    else:
        host, separator, rest = value.rpartition(":")
        if not separator or not host or ":" in host:
            raise ValueError("endereço do pfSense deve informar a porta")
    try:
        port = int(rest)
    except (TypeError, ValueError) as exc:
        raise ValueError("porta do pfSense inválida") from exc
    if not 1 <= port <= 65535:
        raise ValueError("porta do pfSense inválida")
    return host, port


def atomic_config(path: Path, config: dict) -> None:
    """Keep the existing ACL/mode by replacing in the same protected directory."""
    temporary = path.with_name(path.name + "." + os.urandom(8).hex() + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            json.dump(config, output, ensure_ascii=False, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def collect_identity(local_address: Any = None) -> dict:
    """Descriptive telemetry only; never authorization input or a network scan."""
    name = socket.gethostname().strip()
    if (len(name.encode("utf-8")) > 253 or any(
            c.isspace() or unicodedata.category(c) in {"Cc", "Cf"} for c in name)):
        name = ""
    result = {"agent_version": __version__, "os": platform.system().lower()}
    if name:
        result["hostname"] = name
    if local_address:
        try:
            address = ipaddress.ip_address(local_address[0])
            if address.version == 6 and address.ipv4_mapped:
                address = address.ipv4_mapped
            if not (address.is_loopback or address.is_link_local or
                    address.is_unspecified or address.is_multicast):
                result["local_ip"] = str(address)
        except (ValueError, TypeError, IndexError):
            pass
    return result


def validate_policy(policy: Any, pinned_host_key: str) -> dict:
    if not isinstance(policy, dict) or policy.get("control_version") != 1:
        raise ValueError("resposta de controle inválida")
    if policy.get("host_key") and asyncssh.import_public_key(policy["host_key"]) != asyncssh.import_public_key(pinned_host_key):
        raise ValueError("identidade recebida não corresponde ao pfSense")
    if policy.get("endpoint"):
        split_endpoint(policy["endpoint"])
    services = policy.get("services")
    if not isinstance(services, list) or len(services) > 1024:
        raise ValueError("lista de serviços inválida")
    ports = set()
    for service in services:
        if not isinstance(service, dict):
            raise ValueError("serviço inválido recebido do pfSense")
        try:
            ipaddress.ip_address(service["target"])
            port, local_port = service["port"], service["local_port"]
            valid = (type(port) is int and type(local_port) is int and
                     1 <= port <= 65535 and 1024 <= local_port <= 65535 and
                     local_port not in ports and service.get("protocol", "TCP") in {"", "TCP"})
            if not valid:
                raise ValueError()
            ports.add(local_port)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("serviço inválido recebido do pfSense") from exc
    return policy


class PinnedClient(asyncssh.SSHClient):
    def __init__(self, expected: str):
        self.expected = asyncssh.import_public_key(expected)

    def validate_host_public_key(self, host, addr, port, key):
        return key == self.expected


async def global_request(connection, name: str, data: bytes = b"", timeout=REQUEST_TIMEOUT) -> tuple[bool, bytes]:
    result, packet = await asyncio.wait_for(connection._make_global_request(name.encode("ascii"), data), timeout)
    return result == MSG_REQUEST_SUCCESS, packet.get_remaining_payload()


async def gateway_policy(connection, pinned_key: str) -> dict:
    accepted, raw = await global_request(connection, "policy-v1@o3cloudcentral", timeout=10)
    if not accepted:
        raise ConnectionError("pfSense não oferece controle do terminal; atualize o firewall")
    if len(raw) > MAX_POLICY:
        raise ValueError("resposta de controle excede o limite")
    return validate_policy(json.loads(raw), pinned_key)


class AgentControl:
    """A manual pause lasts until this process exits. Every boot reconnects."""
    def __init__(self):
        self._view = {"state": "conectando", "paused": False, "version": __version__, "services": []}
        self.commands: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._done = False

    def snapshot(self) -> dict:
        return copy.deepcopy(self._view)

    def observe(self, state: str, policy: dict | None = None, error: Exception | None = None):
        self._view["state"] = state
        self._view["error"] = str(error)[:500] if error else ""
        if policy is not None:
            self._view["endpoint"] = policy.get("endpoint", "")
            self._view["services"] = copy.deepcopy(policy.get("services", []))
        if state == "conectado":
            self._view["since"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        else:
            self._view.pop("since", None)

    async def command(self, action: str):
        if action not in {"connect", "disconnect", "reconnect"}:
            raise ValueError("comando não permitido")
        if self._done:
            raise RuntimeError("serviço encerrado")
        answer = asyncio.get_running_loop().create_future()
        await asyncio.wait_for(self.commands.put((action, answer)), 2)
        await asyncio.wait_for(answer, 10)


async def _policy_watch(connection, initial: dict, config: dict, path: Path):
    while True:
        await asyncio.sleep(POLICY_INTERVAL)
        new = await gateway_policy(connection, config["gateway_host_key"])
        if new != initial:
            if new.get("endpoint") and new["endpoint"] != config["gateway_endpoint"]:
                config["gateway_endpoint"] = new["endpoint"]
                try:
                    atomic_config(path, config)
                except OSError:
                    LOG.warning("Não foi possível persistir novo endereço do pfSense")
            raise ConnectionError("permissões alteradas; reaplicando")


async def _heartbeat(connection):
    supported = True
    while True:
        if supported:
            payload = json.dumps(collect_identity(connection.get_extra_info("sockname")), separators=(",", ":")).encode()
            if len(payload) <= 1024:
                supported, _ = await global_request(connection, "identity-v1@o3cloudcentral", payload)
        await asyncio.sleep(IDENTITY_INTERVAL)
        accepted, _ = await global_request(connection, "keepalive@o3cloudcentral")
        if not accepted:
            raise ConnectionError("keepalive recusado pelo pfSense")


async def _relay_client(connection, service, reader, writer, slots: set, active: set):
    task = asyncio.current_task()
    if len(slots) >= 64:
        writer.close()
        await writer.wait_closed()
        return
    slots.add(task)
    active.add(writer)
    remote_writer = None
    async def pump(source, target):
        while data := await source.read(65536):
            target.write(data)
            await target.drain()
        try:
            target.write_eof()
        except (OSError, AttributeError):
            pass
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            connection.open_connection(service["target"], service["port"]), 10)
        transfer = [asyncio.create_task(pump(reader, remote_writer)), asyncio.create_task(pump(remote_reader, writer))]
        try:
            await asyncio.gather(*transfer)
        finally:
            for item in transfer:
                item.cancel()
            await asyncio.gather(*transfer, return_exceptions=True)
    except (OSError, asyncssh.Error, asyncio.TimeoutError):
        LOG.info("Serviço indisponível: %s", str(service.get("id", ""))[:100])
    finally:
        slots.discard(task)
        active.discard(writer)
        writer.close()
        if remote_writer:
            remote_writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ConnectionError):
            pass


async def agent_cycle(config: dict, path: Path, control: AgentControl):
    host, port = split_endpoint(config.get("gateway_endpoint", ""))
    pinned_key = config.get("gateway_host_key", "")
    if not pinned_key:
        raise ValueError("terminal sem identidade do pfSense; atualize o instalador")
    signer = asyncssh.import_private_key(config["private_key"])
    control.observe("conectando", {"endpoint": config["gateway_endpoint"], "services": []})
    # An explicit empty known_hosts activates ONLY our key-validation callback.
    # No user keys, SSH agent, password fallback, forwarding agent, or shell.
    async with asyncssh.connect(host, port, username=config["id"], client_keys=[signer],
            client_factory=lambda: PinnedClient(pinned_key), known_hosts=(), agent_path=None,
            password=None, preferred_auth=["publickey"], config=None, connect_timeout=10,
            login_timeout=10, keepalive_interval=0, encoding=None) as connection:
        policy = await gateway_policy(connection, pinned_key)
        if policy.get("endpoint") and policy["endpoint"] != config["gateway_endpoint"]:
            config["gateway_endpoint"] = policy["endpoint"]
            try:
                atomic_config(path, config)
            except OSError:
                LOG.warning("Não foi possível persistir novo endereço do pfSense")
        if not policy["services"]:
            raise PermissionError("nenhum serviço autorizado pelo pfSense")
        listeners, tasks, slots, active = [], [], set(), set()
        try:
            for service in policy["services"]:
                callback = lambda r, w, s=service: _relay_client(connection, s, r, w, slots, active)
                listeners.append(await asyncio.start_server(callback, "127.0.0.1", service["local_port"]))
            control.observe("conectado", policy)
            LOG.info("Conectado ao pfSense; serviços disponíveis=%d", len(listeners))
            tasks = [asyncio.create_task(connection.wait_closed()), asyncio.create_task(_heartbeat(connection)),
                     asyncio.create_task(_policy_watch(connection, policy, config, path))]
            finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in finished:
                task.result()
            raise ConnectionError("túnel encerrado")
        finally:
            for listener in listeners:
                listener.close()
            await asyncio.gather(*(listener.wait_closed() for listener in listeners))
            for writer in tuple(active):
                writer.close()
            for task in tuple(slots):
                task.cancel()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, *tuple(slots), return_exceptions=True)


async def _reconnect(config: dict, path: Path, control: AgentControl):
    delay = 1.0
    while True:
        started = time.monotonic()
        try:
            await agent_cycle(config, path, control)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            control.observe("reconectando", error=exc)
            LOG.warning("Reconexão necessária: %s", str(exc)[:500])
        if time.monotonic() - started > 30:
            delay = 1.0
        await asyncio.sleep(delay + random.random() * .5)
        delay = min(delay * 2, 8.0)


async def run_agent(config_path: str | Path, stop_event: asyncio.Event, control: AgentControl | None = None):
    path = Path(config_path)
    config = json.loads(path.read_text(encoding="utf-8"))
    if config.get("kind") != "agent":
        raise ValueError("configuração não é de terminal")
    control = control or AgentControl()
    control._done = False
    control._view["paused"] = False
    worker = asyncio.create_task(_reconnect(config, path, control))
    stopper = asyncio.create_task(stop_event.wait())
    command_task = asyncio.create_task(control.commands.get())
    try:
        while True:
            finished, _ = await asyncio.wait([stopper, command_task], return_when=asyncio.FIRST_COMPLETED)
            if stopper in finished:
                break
            action, answer = command_task.result()
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
            control._view["paused"] = action == "disconnect"
            if action == "disconnect":
                control.observe("desconectado")
                worker = asyncio.create_task(asyncio.Event().wait())
            else:
                control.observe("conectando")
                worker = asyncio.create_task(_reconnect(config, path, control))
            if not answer.done():
                answer.set_result(None)
            command_task = asyncio.create_task(control.commands.get())
    finally:
        control._done = True
        for task in (worker, stopper, command_task):
            task.cancel()
        await asyncio.gather(worker, stopper, command_task, return_exceptions=True)
        while not control.commands.empty():
            _, answer = control.commands.get_nowait()
            if not answer.done():
                answer.set_exception(RuntimeError("serviço encerrado"))
