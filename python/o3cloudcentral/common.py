"""Shared wire contracts. No terminal runtime request goes to the central."""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

DEFAULT_GATEWAY_LISTEN = "0.0.0.0:2222"
MAX_JSON = 128 << 10
INSTALLER_MAGIC = b"O3CC001!"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def random_token() -> str:
    return secrets.token_urlsafe(32)


def new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(12)


def split_endpoint(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or re.search(r"[\s/\\]", value):
        raise ValueError("Informe IP ou DNS e porta, por exemplo 10.20.0.20:2222.")
    parsed = urlsplit("//" + value)
    if not parsed.hostname or parsed.username or parsed.password or not parsed.port or not 1 <= parsed.port <= 65535:
        raise ValueError("Endereço deve conter IP ou DNS e porta válida.")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Endereço não deve conter caminho ou parâmetros.")
    if ":" in parsed.hostname:
        ipaddress.IPv6Address(parsed.hostname)
    return parsed.hostname, parsed.port


def valid_endpoint(value: str) -> bool:
    try:
        split_endpoint(value)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def valid_url(value: str) -> bool:
    try:
        u = urlsplit(value)
        return bool(u.scheme == "https" and u.hostname and not u.username and not u.password
                    and u.path in ("", "/") and not u.query and not u.fragment
                    and (u.port is None or 1 <= u.port <= 65535)
                    and not re.search(r"[\s\\*%]", u.hostname))
    except (ValueError, TypeError, AttributeError):
        return False


def gateway_portal_url(site: dict) -> str:
    return "https://" + site["endpoint"] if site and valid_endpoint(site.get("endpoint", "")) else ""


def usable_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str):
        raise ValueError("IP inválido.")
    address = ipaddress.ip_address(value)
    if getattr(address, "ipv4_mapped", None):
        address = address.ipv4_mapped
    if "%" in value or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise ValueError("Destino deve ser um IP unicast explícito.")
    return address


def validate_service(service: dict, cidrs: list[str]) -> None:
    if service.get("type", "") not in ("", "HTTP", "HTTPS", "SSH", "TCP"):
        raise ValueError("Tipo de serviço inválido.")
    if service.get("protocol", "TCP") not in ("", "TCP"):
        raise ValueError("Somente o protocolo TCP é suportado.")
    address = usable_ip(service.get("target", ""))
    port, local = service.get("port", 0), service.get("local_port", 0)
    if isinstance(port, bool) or isinstance(local, bool) or not isinstance(port, int) or not isinstance(local, int) or not 1 <= port <= 65535 or not 1024 <= local <= 65535:
        raise ValueError("Portas inválidas; a porta local deve ser maior ou igual a 1024.")
    if not any(address in ipaddress.ip_network(cidr, strict=False) for cidr in cidrs):
        raise ValueError("Destino fora das redes autorizadas deste cliente.")


def selected_services(site: dict, ids: list[str]) -> list[dict]:
    wanted = set(ids)
    return [dict(service) for service in (site.get("services") or []) if service["id"] in wanted]


def validate_selection(site: dict, ids: list[str]) -> bool:
    if not isinstance(ids, list) or not 0 < len(ids) <= 64 or not all(isinstance(x, str) for x in ids) or len(ids) != len(set(ids)):
        return False
    chosen = selected_services(site, ids)
    return len(chosen) == len(ids) and len({s["local_port"] for s in chosen}) == len(chosen)


def normalise_terminal_identity(info: dict) -> dict | None:
    if not isinstance(info, dict) or set(info) - {"hostname", "local_ip", "agent_version", "os"}:
        return None
    result = {}
    hostname = info.get("hostname", "")
    if not isinstance(hostname, str) or len(hostname.encode("utf-8")) > 253 or any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in hostname):
        return None
    hostname = hostname.strip()
    if any(c.isspace() for c in hostname):
        return None
    if hostname:
        result["hostname"] = hostname
    address = info.get("local_ip", "")
    if not isinstance(address, str):
        return None
    if address.strip():
        try:
            parsed = usable_ip(address.strip())
            if getattr(parsed, "ipv4_mapped", None):
                parsed = usable_ip(str(parsed.ipv4_mapped))
            result["local_ip"] = str(parsed)
        except ValueError:
            return None
    for key, limit, pattern in (("agent_version", 64, r"[A-Za-z0-9._+-]*"), ("os", 32, r"[a-z0-9]*")):
        value = info.get(key, "")
        if not isinstance(value, str) or len(value) > limit or not re.fullmatch(pattern, value):
            return None
        if value:
            result[key] = value
    return result or None


def desired_snapshot(state: dict, site: dict) -> dict:
    from .gateway_policy import snapshot_revision
    snapshot = {
        "autonomous": True, "endpoint": site["endpoint"], "devices": [],
        "services": [dict(s) for s in (site.get("services") or [])], "lease_seconds": 300,
    }
    for device in sorted(state["devices"].values(), key=lambda d: d["id"]):
        if device["site_id"] == site["id"] and not device.get("revoked") and device.get("public_key"):
            snapshot["devices"].append({"id": device["id"], "public_key": device["public_key"], "services": selected_services(site, device.get("services", []))})
    snapshot["revision"] = snapshot_revision(snapshot)
    return snapshot


def atomic_json(path: str | Path, value: dict) -> None:
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".o3cloudcentral-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json(path: str | Path) -> dict:
    with Path(path).open(encoding="utf-8") as stream:
        result = json.load(stream)
    if not isinstance(result, dict):
        raise ValueError("Configuração JSON inválida.")
    return result


def tls_context(ca: str) -> ssl.SSLContext:
    context = ssl.create_default_context(cadata=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class APIError(RuntimeError):
    def __init__(self, status: int):
        self.status = status
        self.code = status
        super().__init__(f"Servidor respondeu HTTP {status}.")


async def api_request(config: dict, method: str, route: str, payload=None, *, token: str | None = None) -> dict:
    if not valid_url(config.get("url", "")) or not route.startswith("/"):
        raise ValueError("URL HTTPS inválida.")
    headers = {}
    credential = config.get("token", "") if token is None else token
    if credential:
        headers["Authorization"] = "Bearer " + credential
    async with httpx.AsyncClient(verify=tls_context(config["ca"]), timeout=15, follow_redirects=False, trust_env=False) as client:
        async with client.stream(method, config["url"].rstrip("/") + route, json=payload, headers=headers) as response:
            if response.status_code != 200:
                raise APIError(response.status_code)
            body = bytearray()
            async for part in response.aiter_bytes():
                body.extend(part)
                if len(body) > 2 << 20:
                    raise ValueError("Resposta excede o tamanho permitido.")
            result = json.loads(body)
            if not isinstance(result, dict):
                raise ValueError("Resposta JSON inválida.")
            return result


async def enroll(bundle: dict, config_path: str | Path) -> dict:
    from .crypto import new_key, new_gateway_portal_csr, validate_gateway_portal
    path = Path(config_path)
    if path.exists() or path.is_symlink():
        raise ValueError("Configuração já existe; cadastro não sobrescreve identidade.")
    if bundle.get("kind") not in ("agent", "gateway") or not valid_url(bundle.get("url", "")):
        raise ValueError("Cadastro inválido.")
    private, public = new_key()
    payload = {"kind": bundle["kind"], "token": bundle["token"], "public_key": public}
    portal_key = ""
    if bundle["kind"] == "gateway":
        payload["portal_csr"], portal_key = new_gateway_portal_csr()
    else:
        payload.update(transport="ssh-policy-v1", hostname=socket.gethostname())
    response = await api_request(bundle, "POST", "/api/enroll", payload, token="")
    result = {"kind": bundle["kind"], "id": response["id"], "url": bundle["url"], "ca": bundle["ca"], "token": response["token"], "private_key": private}
    if bundle.get("listen"):
        result["listen"] = bundle["listen"]
    if bundle["kind"] == "agent":
        if not valid_endpoint(response.get("gateway_endpoint", "")) or not response.get("gateway_host_key"):
            raise ValueError("O pfSense precisa estar instalado antes do terminal.")
        result.update(gateway_endpoint=response["gateway_endpoint"], gateway_host_key=response["gateway_host_key"])
    else:
        result.update({k: response[k] for k in ("portal_url", "portal_listen", "portal_cert")})
        result["portal_key"] = portal_key
        validate_gateway_portal(result)
    if path.exists() or path.is_symlink():
        raise ValueError("Configuração criada durante o cadastro; identidade preservada.")
    atomic_json(path, result)
    return result


async def configure_gateway(config_path: str | Path, central_url: str = "") -> dict:
    from .crypto import new_gateway_portal_csr, validate_gateway_portal
    path = Path(config_path)
    original = path.read_bytes()
    config = json.loads(original)
    if config.get("kind") != "gateway" or not all(config.get(k) for k in ("id", "token", "private_key")):
        raise ValueError("Configuração não pertence a um pfSense cadastrado.")
    if central_url:
        config["url"] = central_url.rstrip("/")
    csr, key = new_gateway_portal_csr()
    response = await api_request(config, "POST", "/api/gateway/portal", {"csr": csr})
    config.update({k: response[k] for k in ("portal_url", "portal_listen", "portal_cert")})
    config["portal_key"] = key
    validate_gateway_portal(config)
    if path.read_bytes() != original:
        raise ValueError("Configuração alterada durante a atualização; tente novamente.")
    atomic_json(path, config)
    return config


def embedded_bundle(path: str | Path | None = None) -> dict:
    executable = Path(path or sys.executable)
    with executable.open("rb") as stream:
        stream.seek(-16, os.SEEK_END)
        length, magic = struct.unpack("<Q8s", stream.read(16))
        if magic != INSTALLER_MAGIC or not 0 < length <= 64 << 10 or length > stream.tell() - 16:
            raise ValueError("Executável sem cadastro incorporado.")
        stream.seek(-16 - length, os.SEEK_END)
        bundle = json.loads(stream.read(length))
    if not isinstance(bundle, dict) or bundle.get("kind") != "agent" or not valid_url(bundle.get("url", "")):
        raise ValueError("Cadastro incorporado inválido.")
    return bundle
