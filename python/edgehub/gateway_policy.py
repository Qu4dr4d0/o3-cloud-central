"""Validated, identity-bound autonomous firewall policy.

The revision format deliberately matches the Go 0.4 gateway on the wire so
already enrolled terminals and cached firewall policies can be migrated.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

import asyncssh


def wire_json(value: object) -> bytes:
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    # encoding/json's default HTML-safe output is part of the legacy digest.
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").encode("utf-8")


def _service_wire(service: dict) -> dict:
    out = {key: service.get(key, "" if key in ("id", "name", "target") else 0)
           for key in ("id", "name", "target", "port", "local_port")}
    for key in ("protocol", "type"):
        if service.get(key):
            out[key] = service[key]
    return out


def snapshot_revision(snapshot: dict) -> str:
    """SHA-256 of the original Snapshot struct with Revision omitted."""
    out = {}
    if snapshot.get("autonomous"):
        out["autonomous"] = True
    if snapshot.get("endpoint"):
        out["endpoint"] = snapshot["endpoint"]
    devices = snapshot.get("devices")
    out["devices"] = None if devices is None else [
        {"id": d.get("id", ""), "public_key": d.get("public_key", ""),
         "services": None if d.get("services") is None else [_service_wire(s) for s in d["services"]]}
        for d in devices]
    services = snapshot.get("services")
    out["services"] = None if services is None else [_service_wire(s) for s in services]
    out["lease_seconds"] = snapshot.get("lease_seconds", 0)
    return hashlib.sha256(wire_json(out)).hexdigest()


def endpoint_parts(endpoint: str) -> tuple[str, int]:
    if not isinstance(endpoint, str) or any(c.isspace() for c in endpoint):
        raise ValueError("endereço de escuta inválido")
    if endpoint.startswith("["):
        host, rest = endpoint[1:].split("]", 1)
        if not rest.startswith(":"):
            raise ValueError("porta obrigatória")
        port = rest[1:]
        ipaddress.ip_address(host)
    else:
        host, port = endpoint.rsplit(":", 1)
        if ":" in host:
            raise ValueError("IPv6 deve usar colchetes")
    if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("porta inválida")
    if not host or any(c in host for c in "/\\?#@%"):
        raise ValueError("endereço inválido")
    return host, int(port)


def validate_service(service: dict) -> None:
    if not isinstance(service, dict):
        raise ValueError("serviço inválido")
    target = service.get("target", "")
    if not isinstance(target, str) or "%" in target:
        raise ValueError("IP de serviço inválido")
    ipaddress.ip_address(target)
    for key, length in (("id", 128), ("name", 1024)):
        if not isinstance(service.get(key, ""), str) or len(service.get(key, "").encode()) > length:
            raise ValueError("identificação do serviço inválida")
    for key, low in (("port", 1), ("local_port", 1024)):
        value = service.get(key)
        if type(value) is not int or not low <= value <= 65535:
            raise ValueError("porta de serviço inválida")
    if service.get("protocol", "") not in ("", "TCP"):
        raise ValueError("somente TCP é permitido")


def validate_snapshot(snapshot: dict) -> None:
    if not isinstance(snapshot, dict) or snapshot.get("autonomous") is not True:
        raise ValueError("política autônoma inválida")
    devices = snapshot.get("devices") or []
    services = snapshot.get("services") or []
    if not isinstance(devices, list) or not isinstance(services, list) or len(devices) > 4096 or len(services) > 1024:
        raise ValueError("política excede os limites")
    for service in services:
        validate_service(service)
    ids = set()
    for device in devices:
        if not isinstance(device, dict) or not isinstance(device.get("id"), str) or not device["id"] or len(device["id"].encode()) > 128 or device["id"] in ids:
            raise ValueError("identidade repetida ou inválida")
        ids.add(device["id"])
        public = device.get("public_key", "")
        if not isinstance(public, str) or len(public) > 16384 or len(public.strip().splitlines()) != 1:
            raise ValueError("chave de terminal inválida")
        asyncssh.import_public_key(public)
        local_ports = set()
        device_services = device.get("services") or []
        if not isinstance(device_services, list) or len(device_services) > 1024:
            raise ValueError("serviços do terminal inválidos")
        for service in device_services:
            validate_service(service)
            if service["local_port"] in local_ports:
                raise ValueError("porta local repetida")
            local_ports.add(service["local_port"])
    if snapshot.get("endpoint"):
        endpoint_parts(snapshot["endpoint"])
    if not snapshot.get("revision") or snapshot_revision(snapshot) != snapshot["revision"]:
        raise ValueError("revisão de política inválida")


def atomic_json(path: str, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".edgehub-", dir=target.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(wire_json(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        if os.name != "nt":
            directory = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_policy(path: str, config: dict, host_key: str) -> dict:
    with open(path, "rb") as handle:
        raw = handle.read((4 << 20) + 1)
    if len(raw) > 4 << 20:
        raise ValueError("cache de permissões excede o limite")
    cache = json.loads(raw)
    if cache.get("schema") != 1 or cache.get("gateway_id") != config["id"] or cache.get("host_key") != host_key:
        raise ValueError("cache pertence a outra identidade de firewall")
    validate_snapshot(cache["snapshot"])
    return cache["snapshot"]


def store_policy(path: str, config: dict, host_key: str, snapshot: dict) -> None:
    validate_snapshot(snapshot)
    if path:
        atomic_json(path, {"schema": 1, "gateway_id": config["id"], "host_key": host_key,
                          "synced_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                          "snapshot": copy.deepcopy(snapshot)})


def empty_snapshot() -> dict:
    snapshot = {"autonomous": True, "devices": [], "services": [], "lease_seconds": 0}
    snapshot["revision"] = snapshot_revision(snapshot)
    return snapshot
