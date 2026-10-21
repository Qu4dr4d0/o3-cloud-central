"""FastAPI management plane with transactional MariaDB persistence.

Terminals report through their firewall. Every transaction rechecks tenant and
credential boundaries after the repository obtains its database lock.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import copy
import hashlib
import hmac
import html
import ipaddress
import json
import re
import secrets
import time
import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool

from .common import desired_snapshot, gateway_portal_url, selected_services, valid_endpoint, valid_url, validate_selection, validate_service
from .crypto import check_admin_password, hash_admin_password, issue_gateway_portal, valid_public_key
from .central_artifacts import DEFAULT_PFSENSE_PACKAGE, PFSENSE_PLATFORM, bundle_bytes, checked_artifact, package_digest, pfsense_command, windows_installer_stream
from .linux_artifacts import LINUX_ARTIFACT, installer_prefix, installer_stream, bootstrap_command
from .gateway_policy import validate_snapshot, wire_json

ZERO_TIME = "0001-01-01T00:00:00Z"
MAX_BODY = 128 << 10
BODY_TIMEOUT = 10
MAX_GATEWAY_POLICY_BYTES = 4 << 20
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


class APIError(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None):
        self.status, self.message, self.headers = status, message, headers or {}


def now() -> datetime:
    return datetime.now(timezone.utc)


def stamp(value: datetime | None = None) -> str:
    return (value or now()).isoformat(timespec="microseconds").replace("+00:00", "Z")


def parse_time(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, OverflowError):
        return None


def fresh(value: str | None, seconds: int, moment: datetime | None = None) -> bool:
    value_dt = parse_time(value)
    return value_dt is not None and 0 <= ((moment or now()) - value_dt).total_seconds() < seconds


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def matches(stored: str | None, value: str) -> bool:
    return bool(stored) and hmac.compare_digest(str(stored), digest(value))


def _ticket_active(ticket: dict, moment: datetime | None = None) -> bool:
    expiry = ticket.get("expires")
    if ticket.get("kind") == "agent-link" and expiry in (None, ""):
        return True
    deadline = parse_time(expiry)
    return deadline is not None and deadline > (moment or now())


def _link_projection(ticket: dict) -> dict:
    return {"id": ticket["id"], "services": list(ticket["services"]),
            "created_at": ticket["created"], "expires_at": ticket.get("expires") or None,
            "installation_count": ticket["used_count"]}


def _canonical_public_key(value: str) -> str:
    return serialization.load_ssh_public_key(value.strip().encode()).public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + "\n"


def _public_key_registered(state: dict, public_key: str) -> bool:
    for device in state["devices"].values():
        previous = device.get("public_key")
        if not previous:
            continue
        try:
            if hmac.compare_digest(_canonical_public_key(previous), public_key):
                return True
        except (ValueError, TypeError, UnicodeError):
            continue
    return False


def identity(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict) or set(value) - {"hostname", "local_ip", "agent_version", "os"}:
        return None
    data = {k: value.get(k, "") for k in ("hostname", "local_ip", "agent_version", "os")}
    if any(not isinstance(v, str) for v in data.values()):
        return None
    hostname = data["hostname"]
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs") for c in hostname) or len(hostname.encode("utf-8")) > 253:
        return None
    hostname = hostname.strip()
    if any(c.isspace() for c in hostname):
        return None
    data["hostname"] = hostname
    local_ip = data["local_ip"].strip()
    data["local_ip"] = local_ip
    if local_ip:
        try:
            address = ipaddress.ip_address(local_ip)
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if "%" in local_ip or address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                return None
            data["local_ip"] = str(address)
        except ValueError:
            return None
    if len(data["agent_version"]) > 64 or not re.fullmatch(r"[a-zA-Z0-9._+\-]*", data["agent_version"]):
        return None
    if len(data["os"]) > 32 or not re.fullmatch(r"[a-z0-9]*", data["os"]):
        return None
    return {k: v for k, v in data.items() if v} or None


def _string(data: dict, key: str, default: str = "") -> str:
    value = data.get(key, default)
    if not isinstance(value, str):
        raise APIError(400, "JSON inválido")
    return value


def _strings(data: dict, key: str, default: list | None = None) -> list[str]:
    value = data.get(key, default if default is not None else [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise APIError(400, "JSON inválido")
    return value


def _integer(data: dict, key: str, default: int = 0) -> int:
    value = data.get(key, default)
    if type(value) is not int:
        raise APIError(400, "JSON inválido")
    return value


def _valid_portal_url(value: str) -> bool:
    from urllib.parse import urlsplit
    if not valid_url(value):
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.hostname) and not any(c in parsed.hostname for c in "*% /\\\r\n\t") and parsed.hostname.isascii() and (parsed.port is None or 0 < parsed.port < 65536)
    except (ValueError, TypeError):
        return False


def _bearer(request: Request) -> str:
    value = request.headers.get("authorization", "")
    return value[7:] if value.startswith("Bearer ") else ""


def _gateway_id(state: dict, request: Request) -> str:
    token = _bearer(request)
    return next((sid for sid, site in state["sites"].items() if token and matches(site.get("gateway_hash"), token)), "")


def _device_id(state: dict, request: Request) -> str:
    token = _bearer(request)
    return next((did for did, device in state["devices"].items() if token and not device.get("revoked") and matches(device.get("token_hash"), token)), "")


def _proxy_scope(state: dict, request: Request) -> tuple[str, bool]:
    marker = request.headers.get("x-o3cloudcentral-gateway")
    if marker is None:
        return "", False
    gateway_id = _gateway_id(state, request)
    if marker != "1" or not gateway_id:
        raise APIError(403, "portal não autorizado")
    return gateway_id, True


def _new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(12)


def _default_report() -> dict:
    return {"sessions": {}, "services": [], "version": ""}


class Central:
    def __init__(self, repository: Any, data_dir: Path, *, artifacts: dict | None = None, version: str = "0.7.0"):
        self.repo = repository
        self.data_dir = Path(data_dir)
        self.ca = (self.data_dir / "ca.crt").read_text(encoding="utf-8")
        self.version = version
        paths = artifacts or {}
        self.package = Path(paths.get("pfsense_package", self.data_dir / DEFAULT_PFSENSE_PACKAGE))
        self.installer = Path(paths.get("windows_installer", self.data_dir / "O3CloudCentral.exe"))
        self.linux_installer = Path(paths.get('linux_installer', self.data_dir / LINUX_ARTIFACT))
        self.web = Path(paths.get("web_dir", Path(__file__).resolve().parents[2] / "web"))
        self.icon = Path(paths.get("icon", self.web.parent / "assets" / "O3CloudCentral.ico"))
        self.logo = Path(paths.get("logo", self.web.parent / "assets" / "O3CloudCentral.png"))
        self.failures: dict[str, list[float]] = {}
        self.auth_inflight: dict[str, int] = {}
        self.password_slots = asyncio.Semaphore(2)
        self.probes: dict[str, dict] = {}

    async def read(self) -> dict:
        return await run_in_threadpool(self.repo.read)

    async def tx(self, callback):
        return await run_in_threadpool(self.repo.transaction, callback)

    def rate(self, request: Request, add: bool = False, *, bucket: str = "enrollment"):
        moment = time.monotonic()
        address = bucket + ":" + (request.client.host if request.client else "unknown")
        if len(self.failures) > 4096:
            self.failures = {key: values for key, values in self.failures.items() if values and moment - values[-1] < 60}
            if len(self.failures) > 4096:
                raise APIError(429, "aguarde antes de tentar novamente")
        values = [value for value in self.failures.get(address, []) if moment - value < 60]
        if add:
            values.append(moment)
        self.failures[address] = values
        if len(values) > 20:
            raise APIError(429, "aguarde antes de tentar novamente")

    async def password_work(self, function, *arguments):
        try:
            async with asyncio.timeout(.25):
                await self.password_slots.acquire()
        except TimeoutError:
            raise APIError(429, "Validação de senhas ocupada. Tente novamente em instantes.") from None
        # A disconnected caller must not release its memory/CPU permit
        # while the password thread is still running.
        worker = asyncio.create_task(run_in_threadpool(function, *arguments))
        def completed(task):
            self.password_slots.release()
            if not task.cancelled(): task.exception()
        worker.add_done_callback(completed)
        return await asyncio.shield(worker)

    async def body(self, request: Request, allowed: set[str], *, allow_empty: bool = False) -> dict:
        is_json = request.headers.get("content-type", "").lower().startswith("application/json")
        if not is_json and not allow_empty:
            raise APIError(415, "JSON obrigatório")
        raw = bytearray()
        try:
            async with asyncio.timeout(BODY_TIMEOUT):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_BODY:
                        raise APIError(413, "JSON muito grande")
                    raw.extend(chunk)
        except TimeoutError:
            raise APIError(408, "Tempo esgotado ao receber a solicitação.") from None
        if allow_empty and not raw:
            return {}
        if not is_json:
            raise APIError(415, "JSON obrigatório")
        try:
            def reject_constants(_):
                raise ValueError("non-finite JSON")
            body = json.loads(raw, parse_constant=reject_constants)
        except (json.JSONDecodeError, UnicodeError, ValueError, RecursionError):
            raise APIError(400, "JSON inválido") from None
        def surrogate(value, depth=0):
            if depth > 32:
                raise APIError(400, "JSON excede o limite de profundidade.")
            if isinstance(value, str):
                return any(unicodedata.category(c) == "Cs" for c in value)
            if isinstance(value, dict):
                return any(surrogate(k, depth+1) or surrogate(v, depth+1) for k, v in value.items())
            if isinstance(value, list):
                return any(surrogate(item, depth+1) for item in value)
            return False
        if not isinstance(body, dict) or set(body) - allowed or surrogate(body):
            raise APIError(400, "JSON inválido")
        return body

    async def admin(self, request: Request):
        from .central_auth import authenticate
        return await authenticate(self, request)

    def bundle(self, state: dict, kind: str, object_id: str, *, ttl: int = 900) -> tuple[dict, str]:
        moment = now()
        state["tickets"] = {hashed: ticket for hashed, ticket in state["tickets"].items() if _ticket_active(ticket, moment) and not (ticket["kind"] == kind and ticket["object_id"] == object_id)}
        token = secrets.token_urlsafe(32)
        hashed = digest(token)
        expires = stamp(moment + timedelta(seconds=ttl))
        state["tickets"][hashed] = {"hash": hashed, "kind": kind, "object_id": object_id, "expires": expires}
        bundle = {"kind": "gateway" if kind == "gateway-reinstall" else kind,
                  "url": state["url"], "ca": self.ca, "token": token}
        if kind in ("gateway", "gateway-update", "gateway-reinstall"):
            bundle["listen"] = state["sites"][object_id].get("listen") or "0.0.0.0:2222"
        else:
            bundle["url"] = gateway_portal_url(state["sites"][state["devices"][object_id]["site_id"]])
        return bundle, expires

    def probe_key(self, site: dict) -> str:
        return "\n".join(site.get(key, "") for key in ("endpoint", "listen", "host_key"))

    def probe_address(self, site: dict) -> str:
        from .common import split_endpoint
        try:
            host, _ = split_endpoint(site.get("listen", ""))
            address = ipaddress.ip_address(host)
            if not address.is_unspecified and not address.is_loopback and not address.is_multicast:
                return site["listen"]
        except (ValueError, KeyError):
            pass
        return site["endpoint"]

    async def probe(self, site: dict) -> dict:
        import asyncssh
        from .common import split_endpoint
        address = self.probe_address(site)
        proof = {"key": self.probe_key(site), "address": address, "verified": False}
        try:
            expected = asyncssh.import_public_key(site["host_key"])
        except (ValueError, KeyError):
            return {**proof, "checked_at": stamp(), "reason": "Identidade SSH inválida."}

        class CheckClient(asyncssh.SSHClient):
            def validate_host_public_key(self, host, addr, port, key):
                proof["verified"] = key == expected
                return proof["verified"]
        try:
            host, port = split_endpoint(address)
            async with asyncio.timeout(3):
                conn = await asyncssh.connect(host, port, username="__o3cloudcentral_health__", client_factory=CheckClient, known_hosts=(), client_keys=[], agent_path=None, config=None, preferred_auth="none")
                conn.close()
                await conn.wait_closed()
        except asyncssh.PermissionDenied:
            pass
        except (OSError, asyncssh.Error, TimeoutError, ValueError):
            proof["verified"] = False
        proof["checked_at"] = stamp()
        proof["reason"] = "Contato recente e receptor SSH confirmado." if proof["verified"] else "O receptor SSH não respondeu ou a identidade não corresponde a este cliente."
        return proof

    async def monitor(self):
        semaphore = asyncio.Semaphore(8)
        async def one(site):
            async with semaphore:
                proof = await self.probe(site)
            current = (await self.read())["sites"].get(site["id"])
            if current and proof["key"] == self.probe_key(current):
                self.probes[site["id"]] = proof
        while True:
            try:
                state = await self.read()
                self.probes = {sid: p for sid, p in self.probes.items() if sid in state["sites"]}
                sites = [copy.deepcopy(s) for s in state["sites"].values() if s.get("host_key") and s.get("gateway_hash") and fresh(s.get("last_seen"), 15)]
                await asyncio.gather(*(one(site) for site in sites))
            except asyncio.CancelledError:
                raise
            except Exception:
                import logging
                logging.getLogger(__name__).exception("Falha ao atualizar presença")
            await asyncio.sleep(5)

    def presence(self, site: dict, moment: datetime) -> dict:
        result = {"state": "unknown", "online": False, "contact_fresh": fresh(site.get("last_seen"), 15, moment), "receiver_verified": False, "checked_at": ZERO_TIME, "reason": "Sem contato recente com a gestão; os acessos locais podem continuar funcionando."}
        if not site.get("host_key") or not site.get("gateway_hash"):
            result.update(state="pending", reason="Aguardando instalação do pfSense.")
        elif result["contact_fresh"]:
            proof = self.probes.get(site["id"], {})
            if proof.get("key") != self.probe_key(site) or not fresh(proof.get("checked_at"), 12, moment):
                result.update(state="checking", reason="Contato recebido; aguardando confirmar o receptor SSH.")
            else:
                result.update(state="online" if proof["verified"] else "offline", online=proof["verified"], receiver_verified=proof["verified"], checked_at=proof["checked_at"], address=proof["address"], reason=proof["reason"])
        return result

    def state_view(self, state: dict) -> dict:
        moment = now()
        sites, devices = {}, {}
        for sid, site in state["sites"].items():
            view = copy.deepcopy(site)
            view.pop("gateway_hash", None)
            presence = self.presence(site, moment)
            view["gateway_status"] = presence
            links = {ticket.get('platform','windows'):_link_projection(ticket) for ticket in state['tickets'].values()
                     if ticket.get('kind')=='agent-link' and ticket.get('object_id')==sid and _ticket_active(ticket,moment)}
            view['installation_links'] = links
            view['installation_link'] = links.get('windows')
            view["services"] = []
            report = site.get("report") or _default_report()
            for service in site.get("services") or []:
                health = next((h for h in report.get("services") or [] if h["id"] == service["id"] and fresh(h.get("checked_at"), 45, moment)), None)
                availability = "accessible" if health and health.get("reachable") else "unavailable"
                view["services"].append({**service, "availability": availability if presence["online"] and health else "unverified"})
            view["policy_sync"] = "unknown"
            if presence["contact_fresh"]:
                view["policy_sync"] = "applied" if report.get("policy_revision") == desired_snapshot(state, site)["revision"] else "pending"
            sites[sid] = view
        for did, device in state["devices"].items():
            view = copy.deepcopy(device)
            view.pop("token_hash", None)
            site = sites.get(device["site_id"])
            online = bool(site and not device.get("revoked") and device.get("public_key") and site["gateway_status"]["online"] and ((site.get("report") or {}).get("sessions") or {}).get(did, 0) > 0)
            connection = "online" if online else "offline"
            view.update(online=online, connection_state=connection if site and site["gateway_status"]["state"] in ("online", "offline") else "unknown")
            devices[did] = view
        return {"sites": sites, "devices": devices, "url": state["url"], "now": stamp(moment), "version": self.version, "status_refresh_seconds": 5}

    def pending_device(self, state: dict, device_id: str) -> dict:
        device = state["devices"].get(device_id)
        if not device or device.get("revoked") or device.get("public_key") or device["site_id"] not in state["sites"]:
            raise APIError(400, "terminal já instalado, removido ou inexistente")
        return device

    async def installer_response(self, bundle: dict) -> StreamingResponse:
        try:
            await run_in_threadpool(checked_artifact, self.installer)
        except (OSError, ValueError):
            raise APIError(503, "Instalador Windows indisponível.") from None
        size = self.installer.stat().st_size + len(bundle_bytes(bundle)) + 16
        return StreamingResponse(windows_installer_stream(self.installer, bundle), media_type="application/octet-stream", headers={"Content-Disposition": 'attachment; filename="O3CloudCentral-setup.exe"', "Content-Length": str(size)})

    async def linux_installer_response(self, bundle: dict) -> StreamingResponse:
        try:
            checksum = await run_in_threadpool(package_digest,self.linux_installer)
        except (OSError,ValueError):
            raise APIError(503,'Instalador Debian/Ubuntu indisponível.') from None
        prefix = installer_prefix(bundle,checksum)
        return StreamingResponse(installer_stream(self.linux_installer,prefix),media_type='application/x-sh',
            headers={'Content-Disposition':'attachment; filename="O3CloudCentral-setup-debian.sh"',
                     'Content-Length':str(len(prefix)+self.linux_installer.stat().st_size)})

    async def public_bundle(self, request: Request, token: str) -> tuple[dict, dict, dict]:
        self.rate(request)
        state = await self.read()
        proxy_id, proxied = _proxy_scope(state, request)
        ticket = state["tickets"].get(digest(token), {})
        reusable = ticket.get("kind") == "agent-link"
        if reusable:
            site = state["sites"].get(ticket.get("object_id"), {})
            device = {"name": site.get("name", ""), "services": [service["name"] for service in selected_services(site, ticket.get("services") or [])]}
            valid = bool(proxied and site and proxy_id == site["id"] and validate_selection(site, ticket.get("services") or []))
        else:
            device = state["devices"].get(ticket.get("object_id"), {})
            site = state["sites"].get(device.get("site_id"), {})
            valid = bool(ticket.get("kind") == "agent" and device and not device.get("revoked") and not device.get("public_key") and site and (not proxied or proxy_id == device["site_id"]))
        valid = bool(TOKEN_RE.fullmatch(token) and _ticket_active(ticket) and valid and valid_url(gateway_portal_url(site)))
        if not valid:
            self.rate(request, True)
            raise APIError(403, "Link expirado, cancelado ou já utilizado. Solicite um novo link ao responsável.")
        return {"kind": "agent", "url": gateway_portal_url(site), "ca": self.ca, "token": token}, device, ticket


def create_app(repository: Any, data_dir: Path | str, *, artifacts: dict | None = None, version: str = "0.7.0", monitor: bool = True) -> FastAPI:
    central = Central(repository, Path(data_dir), artifacts=artifacts, version=version)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(central.monitor()) if monitor else None
        try:
            yield
        finally:
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="O3 Cloud Central", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.central = central

    @app.exception_handler(APIError)
    async def api_error(request, exception):
        return PlainTextResponse(exception.message + "\n", status_code=exception.status, headers=exception.headers)

    @app.middleware("http")
    async def headers(request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("Falha ao processar requisição")
            response = PlainTextResponse("Falha interna ao processar a solicitação.\n", status_code=500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        return response

    @app.get("/healthz")
    async def health():
        return {"service": "O3 Cloud Central", "version": version}

    @app.get("/brand/logo.png")
    async def logo():
        if not central.logo.is_file():
            raise APIError(404, "logo não encontrado")
        return FileResponse(central.logo, media_type="image/png")

    @app.get("/favicon.ico")
    async def icon():
        if not central.icon.is_file():
            raise APIError(404, "ícone não encontrado")
        return FileResponse(central.icon, media_type="image/x-icon")

    @app.get("/")
    @app.get("/app.js")
    @app.get("/theme.js")
    @app.get("/style.css")
    @app.get("/login.js")
    @app.get("/first-access.js")
    async def panel(request: Request):
        if request.url.path == "/":
            from .central_auth import authenticate
            from fastapi.responses import RedirectResponse
            try: await authenticate(central, request, allow_basic=False)
            except APIError as error:
                if error.status == 401: return RedirectResponse('/login', status_code=303)
                if error.status == 403: return RedirectResponse('/first-access', status_code=303)
                raise
        path = "index.html" if request.url.path == "/" else request.url.path[1:]
        types = {".html": "text/html", ".js": "text/javascript", ".css": "text/css"}
        target = central.web / path
        if not target.is_file():
            raise APIError(503, "Painel indisponível.")
        return FileResponse(target, media_type=types[target.suffix])

    @app.get("/api/admin/state")
    async def admin_state(request: Request):
        username = await central.admin(request)
        return {**central.state_view(request.state.auth_state), 'username':username}

    @app.post("/api/admin/account/password")
    async def password(request: Request):
        username = await central.admin(request)
        body = await central.body(request, {"current_password", "new_password"})
        current, new = _string(body, "current_password"), _string(body, "new_password")
        if len(new) < 12 or len(new.encode()) > 256 or current == new:
            raise APIError(400, "Escolha uma senha diferente, com pelo menos 12 caracteres e no máximo 256 bytes.")
        from .central_auth import password_hash
        previous_hash = password_hash(request.state.auth_state, username)
        if not await central.password_work(check_admin_password, previous_hash, current):
            raise APIError(400, "Senha atual incorreta.")
        hashed = await central.password_work(hash_admin_password, new)
        def change(state):
            if password_hash(state, username) != previous_hash:
                raise APIError(409, "Senha alterada por outra sessão. Entre novamente.")
            if username == 'admin': state['admin_hash'] = hashed
            else: state['users'][username]['password_hash'] = hashed
            if 'sessions' in state:
                state['sessions'] = {key:value for key,value in state['sessions'].items() if value['username'] != username}
        await central.tx(change)
        try:
            if username == 'admin': (central.data_dir / "admin-password.txt").unlink(missing_ok=True)
        except OSError:
            import logging
            logging.getLogger(__name__).warning("Senha alterada; arquivo da senha inicial não pôde ser removido.")
        return {"ok": True, "reauthenticate": True}

    @app.post("/api/admin/sites")
    async def add_site(request: Request):
        await central.admin(request)
        data = await central.body(request, {"name", "endpoint", "portal_url", "cidrs", "listen"})
        name, endpoint, portal = _string(data, "name"), _string(data, "endpoint"), _string(data, "portal_url")
        listen, cidrs = _string(data, "listen") or "0.0.0.0:2222", _strings(data, "cidrs")
        if not 0 < len(name.encode()) <= 120 or len(endpoint) > 320 or len(listen) > 320 or not valid_endpoint(endpoint) or not valid_endpoint(listen) or len(cidrs) > 32 or portal and not _valid_portal_url(portal):
            raise APIError(400, "nome, redes e endereços válidos são obrigatórios")
        try:
            if any(ipaddress.ip_network(cidr, strict=False).prefixlen == 0 for cidr in cidrs):
                raise ValueError
        except ValueError:
            raise APIError(400, "rede inválida") from None
        site = {"id": _new_id("vps_"), "name": name, "endpoint": endpoint, "listen": listen, "cidrs": cidrs, "automatic_targets": not bool(cidrs), "host_key": "", "services": [], "last_seen": ZERO_TIME, "report": _default_report()}
        if portal:
            site["portal_url"] = portal.rstrip("/")
        await central.tx(lambda state: state["sites"].update({site["id"]: site}))
        return site

    @app.patch("/api/admin/sites/{site_id}")
    async def patch_site(site_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {"endpoint", "portal_url", "cidrs"})
        if not data:
            raise APIError(400, "informe os dados do cliente")
        updates = {}
        for field in ("endpoint", "portal_url"):
            if field not in data:
                continue
            value = _string(data, field)
            if field == "endpoint" and (len(value) > 320 or not valid_endpoint(value)) or field == "portal_url" and value and not _valid_portal_url(value):
                raise APIError(400, "endereço inválido")
            updates[field] = value.rstrip("/") if field == "portal_url" else value
        if "cidrs" in data:
            cidrs = _strings(data, "cidrs")
            if not cidrs or len(cidrs) > 32:
                raise APIError(400, "Informe entre 1 e 32 redes internas.")
            try:
                networks = [ipaddress.ip_network(value, strict=False) for value in cidrs]
                if any(network.prefixlen == 0 for network in networks):
                    raise ValueError
            except ValueError:
                raise APIError(400, "Rede interna inválida. Use o formato 192.168.10.0/24; redes /0 não são permitidas.") from None
            updates.update(cidrs=list(dict.fromkeys(str(network) for network in networks)), automatic_targets=False)
        def change(state):
            site = state["sites"].get(site_id)
            if not site:
                raise APIError(404, "cliente não encontrado")
            if "cidrs" in updates:
                for service in site.get("services") or []:
                    try:
                        validate_service(service, updates["cidrs"])
                    except ValueError:
                        raise APIError(400, "As redes informadas não incluem o serviço " + service["name"] + " (" + service["target"] + "). Mantenha a rede desse serviço ou remova-o antes de alterar as redes.") from None
            site.update(updates)
        await central.tx(change)
        if "endpoint" in updates or "portal_url" in updates:
            central.probes.pop(site_id, None)
        return {"ok": True}

    @app.delete("/api/admin/sites/{site_id}")
    async def remove_site(site_id: str, request: Request):
        await central.admin(request)
        def change(state):
            if site_id not in state["sites"]:
                raise APIError(404, "cliente não encontrado")
            devices = {did for did, d in state["devices"].items() if d["site_id"] == site_id}
            state["devices"] = {did: d for did, d in state["devices"].items() if did not in devices}
            state["tickets"] = {key: t for key, t in state["tickets"].items() if not ((t["kind"] in ("gateway", "gateway-update", "gateway-reinstall", "agent-link") and t["object_id"] == site_id) or t["object_id"] in devices)}
            del state["sites"][site_id]
        await central.tx(change)
        central.probes.pop(site_id, None)
        return {"ok": True}

    @app.post("/api/admin/sites/{site_id}/services")
    async def add_service(site_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {"id", "name", "target", "port", "local_port", "protocol", "type"})
        service = {"id": _new_id("svc_"), "name": _string(data, "name"), "target": _string(data, "target"), "port": _integer(data, "port"), "local_port": _integer(data, "local_port"), "protocol": _string(data, "protocol") or "TCP", "type": _string(data, "type") or "TCP"}
        def change(state):
            site = state["sites"].get(site_id)
            if not site:
                raise APIError(404, "cliente não encontrado")
            site["services"] = site.get("services") or []
            if not 0 < len(service["name"].encode()) <= 120 or len(site["services"]) >= 128:
                raise APIError(400, "nome inválido ou limite de serviços atingido")
            used = {item["local_port"] for item in site["services"]}
            if not service["local_port"]:
                service["local_port"] = next((p for p in range(20000, 60001) if p not in used), 0)
            if service["local_port"] in used:
                raise APIError(400, "endereço de acesso local já reservado neste cliente")
            if site.get("automatic_targets"):
                site["cidrs"] = site.get("cidrs") or []
                try:
                    ip = ipaddress.ip_address(service["target"])
                    if ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast or "%" in service["target"]:
                        raise ValueError
                    prefix = str(ip) + "/" + str(ip.max_prefixlen)
                except ValueError:
                    raise APIError(400, "destino deve ser um IP unicast explícito") from None
                if prefix not in site["cidrs"]:
                    site["cidrs"].append(prefix)
            try:
                validate_service(service, site.get("cidrs") or [])
            except ValueError as exc:
                raise APIError(400, str(exc)) from None
            site["services"].append(service)
        await central.tx(change)
        return service

    @app.delete("/api/admin/sites/{site_id}/services/{service_id}")
    async def remove_service(site_id: str, service_id: str, request: Request):
        await central.admin(request)
        def change(state):
            site = state["sites"].get(site_id)
            if not site or not any(svc["id"] == service_id for svc in site.get("services") or []):
                raise APIError(404, "serviço não encontrado neste cliente")
            site["services"] = [svc for svc in site["services"] if svc["id"] != service_id]
            for device in state["devices"].values():
                if device["site_id"] == site_id:
                    device["services"] = [sid for sid in device["services"] if sid != service_id]
            for hashed, ticket in list(state["tickets"].items()):
                if ticket.get("kind") == "agent-link" and ticket.get("object_id") == site_id:
                    ticket["services"] = [sid for sid in ticket["services"] if sid != service_id]
                    if not ticket["services"]:
                        del state["tickets"][hashed]
            if site.get("automatic_targets"):
                site["cidrs"] = list(dict.fromkeys(str(ipaddress.ip_network(svc["target"], strict=False)) for svc in site["services"]))
            report = site.get("report") or _default_report()
            site["report"] = report
            report["services"] = [health for health in report.get("services") or [] if health["id"] != service_id]
        await central.tx(change)
        return {"ok": True}

    @app.post("/api/admin/devices")
    async def add_device(request: Request):
        await central.admin(request)
        data = await central.body(request, {"name", "site_id", "services"})
        name, site_id, services = _string(data, "name").strip(), _string(data, "site_id"), _strings(data, "services")
        did = _new_id("dev_")
        device = {"id": did, "site_id": site_id, "name": name or "Novo terminal " + did[-6:], "automatic_name": not bool(name), "services": services, "public_key": "", "revoked": False, "last_seen": ZERO_TIME, "status": "aguardando instalação"}
        def change(state):
            site = state["sites"].get(site_id)
            if not site or len(name.encode()) > 120 or not validate_selection(site, services):
                raise APIError(400, "cliente, nome ou serviços inválidos")
            state["devices"][did] = device
        await central.tx(change)
        return device

    @app.patch("/api/admin/devices/{device_id}/services")
    async def patch_device(device_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {"services"})
        services = _strings(data, "services")
        def change(state):
            device = state["devices"].get(device_id)
            site = state["sites"].get(device["site_id"]) if device else None
            if not site or not validate_selection(site, services):
                raise APIError(400, "serviços inválidos")
            device["services"] = services
        await central.tx(change)
        return {"ok": True}

    @app.post("/api/admin/devices/{device_id}/revoke")
    async def revoke_device(device_id: str, request: Request):
        await central.admin(request)
        def change(state):
            device = state["devices"].get(device_id)
            if not device:
                raise APIError(404, "terminal inexistente")
            device.update(revoked=True, status="revogado")
            state["tickets"] = {key: ticket for key, ticket in state["tickets"].items() if ticket["object_id"] != device_id}
        await central.tx(change)
        return {"ok": True}

    @app.post("/api/admin/sites/{site_id}/bootstrap")
    async def bootstrap_gateway(site_id: str, request: Request):
        await central.admin(request)
        await central.body(request, set())
        def change(state):
            site = state["sites"].get(site_id)
            if not site or site.get("gateway_hash"):
                raise APIError(400, "cliente inexistente ou já cadastrado")
            return central.bundle(state, "gateway", site_id)[0]
        return await central.tx(change)

    @app.post("/api/admin/sites/{site_id}/install-link")
    async def site_install_link(site_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {"services", "platform"})
        services = _strings(data, "services")
        platform = _string(data,'platform') or 'windows'
        if platform not in ('windows','debian'): raise APIError(400,'Sistema operacional inválido.')
        try:
            checked_artifact(central.linux_installer if platform=='debian' else central.installer)
        except (OSError, ValueError):
            raise APIError(503, "Instalador indisponível para este sistema operacional.") from None
        token = secrets.token_urlsafe(32)
        hashed = digest(token)
        def change(state):
            site = state["sites"].get(site_id)
            if not site:
                raise APIError(404, "cliente não encontrado")
            if not validate_selection(site, services):
                raise APIError(400, "serviços inválidos")
            # Rotation invalidates only this site's previous reusable token.
            # Already enrolled terminals have independent keys and credentials.
            state["tickets"] = {key: ticket for key, ticket in state["tickets"].items()
                                if _ticket_active(ticket) and not (ticket.get("kind") == "agent-link" and ticket.get("object_id") == site_id and ticket.get('platform','windows')==platform)}
            ticket = {"hash": hashed, "kind": "agent-link", "object_id": site_id,
                      "id": _new_id("lnk_"), "services": list(services), "created": stamp(),
                      "expires": None, "used_count": 0}
            if platform=='debian': ticket['platform']='debian'
            state["tickets"][hashed] = ticket
            url = gateway_portal_url(site) + '/install/windows/' + token
            result = {'url':url, **_link_projection(ticket)}
            if platform=='debian': result['command']=bootstrap_command(url+'/installer.exe',central.ca)
            return result
        return await central.tx(change)

    @app.delete("/api/admin/sites/{site_id}/install-link")
    async def revoke_site_install_link(site_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {'platform'}, allow_empty=True)
        platform = _string(data,'platform') or 'windows'
        if platform not in ('windows','debian'): raise APIError(400,'Sistema operacional inválido.')
        def change(state):
            if site_id not in state["sites"]:
                raise APIError(404, "cliente não encontrado")
            state["tickets"] = {key: ticket for key, ticket in state["tickets"].items()
                                if not (ticket.get("kind") == "agent-link" and ticket.get("object_id") == site_id and ticket.get('platform','windows')==platform)}
        await central.tx(change)
        return {"ok": True}

    @app.post("/api/admin/sites/{site_id}/install-command")
    @app.post("/api/admin/sites/{site_id}/update-command")
    @app.post("/api/admin/sites/{site_id}/reinstall-command")
    async def gateway_command(site_id: str, request: Request):
        await central.admin(request)
        await central.body(request, set())
        update = request.url.path.endswith("/update-command")
        reinstall = request.url.path.endswith("/reinstall-command")
        try:
            checksum = await run_in_threadpool(package_digest, central.package)
        except (OSError, ValueError):
            raise APIError(503, "Pacote pfSense indisponível na central.") from None
        def change(state):
            site = state["sites"].get(site_id)
            enrolled = bool(site and site.get("gateway_hash") and site.get("host_key"))
            if not site or not reinstall and (update != enrolled or not update and (site.get("gateway_hash") or site.get("host_key"))):
                raise APIError(400, "cliente inexistente ou estado de instalação incompatível")
            ticket_kind = "gateway-reinstall" if reinstall else "gateway-update" if update else "gateway"
            bundle, expires = central.bundle(state, ticket_kind, site_id)
            return {"command": pfsense_command(bundle, checksum, update=update, replace_site_id=site_id if reinstall else ""), "expires_at": expires, "sha256": checksum, "platform": PFSENSE_PLATFORM}
        return await central.tx(change)

    @app.post("/api/admin/installer-download")
    async def download_terminal_installer(request: Request):
        await central.admin(request)
        data = await central.body(request, {"token"})
        token = _string(data, "token")
        if not TOKEN_RE.fullmatch(token):
            raise APIError(403, "Cadastro de instalação inválido.")
        state = await central.read()
        ticket = state["tickets"].get(digest(token), {})
        site = {}
        if ticket.get("kind") == "agent-link":
            site = state["sites"].get(ticket.get("object_id"), {})
            valid = bool(site and validate_selection(site, ticket.get("services") or []))
        elif ticket.get("kind") == "agent":
            device = state["devices"].get(ticket.get("object_id"), {})
            site = state["sites"].get(device.get("site_id"), {})
            valid = bool(site and device and not device.get("revoked") and not device.get("public_key") and validate_selection(site, device.get("services") or []))
        else:
            valid = False
        platform = ticket.get("platform", "windows")
        if not (valid and _ticket_active(ticket) and valid_url(gateway_portal_url(site)) and platform in ("windows", "debian")):
            raise APIError(403, "Link expirado, revogado ou indisponível. Gere uma nova instalação.")
        bundle = {"kind":"agent", "url":gateway_portal_url(site), "ca":central.ca, "token":token}
        return await central.linux_installer_response(bundle) if platform == "debian" else await central.installer_response(bundle)

    @app.get("/api/install/pfsense/{token}/package")
    async def install_package(token: str, request: Request):
        central.rate(request)
        state = await central.read()
        ticket = state["tickets"].get(digest(token), {})
        site = state["sites"].get(ticket.get("object_id"), {})
        enrolled = bool(site.get("gateway_hash") and site.get("host_key"))
        _, proxied = _proxy_scope(state, request)
        valid = bool(not proxied and TOKEN_RE.fullmatch(token) and site and _ticket_active(ticket) and (ticket.get("kind") == "gateway-reinstall" or ticket.get("kind") == "gateway-update" and enrolled or ticket.get("kind") == "gateway" and not site.get("gateway_hash") and not site.get("host_key")))
        if not valid:
            central.rate(request, True)
            raise APIError(403, "cadastro inválido ou expirado")
        try:
            checked_artifact(central.package)
        except (OSError, ValueError):
            raise APIError(503, "pacote indisponível") from None
        return FileResponse(central.package, media_type="application/octet-stream", filename=central.package.name)

    @app.post("/api/admin/devices/{device_id}/bootstrap")
    @app.post("/api/admin/devices/{device_id}/installer")
    @app.post("/api/admin/devices/{device_id}/install-link")
    async def bootstrap_device(device_id: str, request: Request):
        await central.admin(request)
        data = await central.body(request, {'platform'})
        platform = _string(data,'platform') or 'windows'
        if platform not in ('windows','debian'): raise APIError(400,'Sistema operacional inválido.')
        mode = request.url.path.rsplit("/", 1)[-1]
        if mode != "bootstrap":
            try:
                checked_artifact(central.linux_installer if platform=='debian' else central.installer)
            except (OSError, ValueError):
                raise APIError(503, "Instalador solicitado indisponível.") from None
        def change(state):
            central.pending_device(state, device_id)
            result = central.bundle(state, "agent", device_id, ttl=86400 if mode == "install-link" else 900)
            if platform=='debian': state['tickets'][digest(result[0]['token'])]['platform']='debian'
            return result
        bundle, expires = await central.tx(change)
        if mode == "install-link":
            url = bundle['url'].rstrip('/')+'/install/windows/'+bundle['token']
            result = {'url':url,'expires_at':expires}
            if platform=='debian': result['command']=bootstrap_command(url+'/installer.exe',central.ca)
            return result
        if mode=='installer':
            return await central.linux_installer_response(bundle) if platform=='debian' else await central.installer_response(bundle)
        return bundle

    @app.get("/install/windows.css")
    async def install_css():
        return FileResponse(central.web / "install.css", media_type="text/css")

    @app.get("/install/windows/{token}")
    async def install_page(token: str, request: Request):
        bundle, device, ticket = await central.public_bundle(request, token)
        reusable = ticket.get("kind") == "agent-link"
        deadline = parse_time(ticket.get("expires"))
        expires = deadline.strftime("%d/%m/%Y %H:%M UTC") if deadline else ""
        if reusable:
            permitted = ", ".join(device["services"])
            details = '<p class="hint">Serviços permitidos: ' + html.escape(permitted) + '.</p>'
            usage = "Este link pode ser usado em vários computadores deste cliente. Cada instalação terá sua própria identidade e acesso apenas aos serviços permitidos."
            usage += " Válido até " + expires + "." if expires else " Válido até ser revogado pelo responsável."
        else:
            details = ""
            usage = "Este link é para uma única máquina. Baixar não consome o cadastro; a instalação conclui o uso. Válido até " + expires + "."
        download = "/install/windows/" + token + "/installer.exe"
        # Keep the legacy relay URL so Linux also works through already
        # installed pfSense packages. Only the scoped ticket selects the OS.
        if ticket.get('platform')=='debian':
            command = bootstrap_command(bundle['url'].rstrip('/')+download,central.ca)
            return HTMLResponse('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Instalar O3 Cloud Central — Debian/Ubuntu</title><link rel="icon" href="/favicon.ico"><link rel="stylesheet" href="/install/windows.css"><main><div class="brand"><img class="brand-logo" src="/brand/logo.png" width="92" height="56" alt=""><span>O3 Cloud Central</span></div><h1>Instalar no Debian/Ubuntu</h1><p class="name">'+html.escape(device['name'])+'</p>'+details+'<p>Linux amd64 (x86_64), com systemd. O Python e as dependências já estão incluídos.</p><a class="download" href="'+download+'">Baixar instalador Debian/Ubuntu</a><p>Execute o arquivo baixado como root: <code>sudo sh O3CloudCentral-setup-debian.sh</code></p><p>Ou execute este comando como root no servidor:</p><textarea rows="7" readonly spellcheck="false" aria-label="Comando de instalação">'+html.escape(command)+'</textarea><p class="hint">Estado: <code>sudo o3cloudcentral-agent status</code><br>Remover: <code>sudo o3cloudcentral-agent uninstall</code></p><p class="hint">'+usage+'</p></main></html>',headers={'X-Robots-Tag':'noindex, nofollow, noarchive'})
        return HTMLResponse('<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>Instalar O3 Cloud Central</title><link rel="icon" href="/favicon.ico" type="image/x-icon"><link rel="stylesheet" href="/install/windows.css"><main><div class="brand"><img class="brand-logo" src="/brand/logo.png" width="92" height="56" alt="" aria-hidden="true"><span>O3 Cloud Central</span></div><h1>Instalar neste computador</h1><p class="name">' + html.escape(device["name"]) + '</p>' + details + '<p>Baixe o instalador e execute-o. Confirme a solicitação de administrador do Windows.</p><a class="download" href="' + download + '">Baixar instalador Windows</a><p class="hint">O ícone do O3 Cloud Central aparecerá ao lado do relógio. Clique com o botão direito para conectar, desconectar e ver o status.</p><p class="hint">' + usage + '</p></main></html>', headers={"X-Robots-Tag": "noindex, nofollow, noarchive"})

    @app.get("/install/windows/{token}/installer.exe")
    async def public_installer(token: str, request: Request):
        bundle, _, ticket = await central.public_bundle(request, token)
        return await central.linux_installer_response(bundle) if ticket.get('platform')=='debian' else await central.installer_response(bundle)

    @app.post("/api/enroll")
    async def enroll(request: Request):
        central.rate(request)
        data = await central.body(request, {"token", "kind", "public_key", "hostname", "transport", "portal_csr"})
        token, kind, public_key = _string(data, "token"), _string(data, "kind"), _string(data, "public_key")
        hostname, transport, csr = _string(data, "hostname"), _string(data, "transport"), _string(data, "portal_csr")
        if not valid_public_key(public_key):
            raise APIError(400, "chave Ed25519 obrigatória")
        public_key = _canonical_public_key(public_key)
        new_token = secrets.token_urlsafe(32)
        def change(state):
            proxy_id, proxied = _proxy_scope(state, request)
            if proxied and kind != "agent":
                raise APIError(403, "portal não autorizado")
            ticket = state["tickets"].get(digest(token), {})
            reusable = ticket.get("kind") == "agent-link" and kind == "agent"
            reinstall = ticket.get("kind") == "gateway-reinstall" and kind == "gateway"
            if not TOKEN_RE.fullmatch(token) or not (ticket.get("kind") == kind or reusable or reinstall) or not _ticket_active(ticket):
                raise APIError(403, "cadastro inválido, expirado ou utilizado")
            object_id = ticket["object_id"]
            response = {"id": object_id, "token": new_token, "gateway_endpoint": "", "gateway_host_key": ""}
            if kind == "gateway":
                site = state["sites"].get(object_id)
                if not site or site.get("gateway_hash") and not reinstall:
                    raise APIError(403, "cadastro inválido")
                if csr:
                    try:
                        response.update(issue_gateway_portal(central.data_dir, site, csr))
                    except (ValueError, OSError):
                        raise APIError(403, "CSR de portal inválido") from None
                site.update(host_key=public_key.strip() + "\n", gateway_hash=digest(new_token))
                if reinstall:
                    site.update(last_seen=ZERO_TIME, last_source="", report=_default_report())
            elif kind == "agent":
                if _public_key_registered(state, public_key):
                    raise APIError(403, "chave do terminal já cadastrada")
                if reusable:
                    site = state["sites"].get(object_id)
                    if not proxied or not site or proxy_id != site["id"]:
                        raise APIError(403, "terminal não pertence a este portal")
                    if not site.get("host_key") or not site.get("gateway_hash"):
                        raise APIError(403, "instale o pfSense antes do terminal")
                    if not validate_selection(site, ticket.get("services") or []):
                        raise APIError(403, "serviços deste link não estão mais disponíveis")
                    object_id = _new_id("dev_")
                    while object_id in state["devices"]:
                        object_id = _new_id("dev_")
                    device = {"id": object_id, "site_id": site["id"],
                              "name": "Novo terminal " + object_id[-6:], "automatic_name": True,
                              "services": list(ticket["services"]), "public_key": "", "revoked": False,
                              "last_seen": ZERO_TIME, "status": "aguardando instalação"}
                    state["devices"][object_id] = device
                    response["id"] = object_id
                else:
                    device = state["devices"].get(object_id)
                if not device or device.get("revoked") or device.get("public_key"):
                    raise APIError(403, "cadastro inválido")
                site = state["sites"].get(device["site_id"])
                if not site or proxied and proxy_id != device["site_id"]:
                    raise APIError(403, "terminal não pertence a este portal")
                if transport == "ssh-policy-v1" and not site.get("host_key"):
                    raise APIError(403, "instale o pfSense antes do terminal")
                clean = identity({"hostname": hostname})
                if clean:
                    device["hostname"] = clean["hostname"]
                    if device.get("automatic_name") and len(clean["hostname"]) <= 120:
                        device["name"] = clean["hostname"]
                device.update(public_key=public_key.strip() + "\n", token_hash=digest(new_token), status="cadastrado")
                # The complete candidate policy must fit the firewall receiver.
                # Rejecting here rolls back the new identity, credentials and
                # link counter together instead of breaking future policy sync.
                snapshot = desired_snapshot(state, site)
                try:
                    validate_snapshot(snapshot)
                    encoded = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
                    cache = {"schema": 1, "gateway_id": site["id"], "host_key": site["host_key"],
                             "synced_at": stamp(), "snapshot": snapshot}
                    # The firewall persists this envelope with HTML-safe JSON
                    # and a trailing newline. It must also fit after a restart.
                    if len(encoded) > MAX_GATEWAY_POLICY_BYTES or len(wire_json(cache)) + 1 > MAX_GATEWAY_POLICY_BYTES:
                        raise ValueError("política excede o limite de tamanho")
                except ValueError:
                    raise APIError(409, "capacidade de política do pfSense atingida; nenhum terminal foi cadastrado") from None
                response.update(gateway_endpoint=site["endpoint"], gateway_host_key=site["host_key"])
            else:
                raise APIError(403, "cadastro inválido")
            if reusable:
                ticket["used_count"] += 1
            else:
                del state["tickets"][digest(token)]
            if reinstall:
                state["tickets"] = {hashed: current for hashed, current in state["tickets"].items()
                                    if not (current["object_id"] == object_id and
                                            current["kind"] in ("gateway-update", "gateway-reinstall"))}
            return response
        try:
            return await central.tx(change)
        except APIError:
            central.rate(request, True)
            raise

    @app.post("/api/gateway/portal")
    async def gateway_portal(request: Request):
        data = await central.body(request, {"csr"})
        csr = _string(data, "csr")
        def issue(state):
            gateway_id = _gateway_id(state, request)
            if not gateway_id:
                raise APIError(403, "não autorizado")
            try:
                return issue_gateway_portal(central.data_dir, state["sites"][gateway_id], csr)
            except ValueError:
                raise APIError(400, "CSR de portal inválido") from None
        return await central.tx(issue)

    @app.post("/api/gateway/sync")
    async def gateway_sync(request: Request):
        data = await central.body(request, {"sessions", "services", "version", "policy_revision", "terminals"})
        sessions = {} if data.get("sessions") is None else data["sessions"]
        health = [] if data.get("services") is None else data["services"]
        terminals = {} if data.get("terminals") is None else data["terminals"]
        if not isinstance(sessions, dict) or not isinstance(health, list) or not isinstance(terminals, dict):
            raise APIError(400, "relatório inválido")
        version_in, revision = _string(data, "version"), _string(data, "policy_revision")
        if len(version_in) > 64 or len(revision) > 128:
            raise APIError(400, "relatório inválido")
        for count in sessions.values():
            if type(count) is not int:
                raise APIError(400, "relatório inválido")
        for entry in health:
            if not isinstance(entry, dict) or set(entry) - {"id", "reachable", "checked_at"} or not isinstance(entry.get("id"), str) or type(entry.get("reachable")) is not bool or not parse_time(entry.get("checked_at")):
                raise APIError(400, "relatório de serviços inválido")
        def change(state):
            gateway_id = _gateway_id(state, request)
            if not gateway_id:
                raise APIError(403, "não autorizado")
            site = state["sites"][gateway_id]
            valid_sessions = {did: count for did, count in sessions.items() if did in state["devices"] and state["devices"][did]["site_id"] == gateway_id and not state["devices"][did].get("revoked") and state["devices"][did].get("public_key") and 0 <= count <= 4}
            allowed = {service["id"] for service in site["services"]}
            valid_health = [entry for entry in health if entry["id"] in allowed]
            valid_terminals = {}
            for did, info in terminals.items():
                if valid_sessions.get(did, 0) <= 0:
                    continue
                clean = identity(info)
                if clean:
                    valid_terminals[did] = clean
                    state["devices"][did].update(clean)
            site["last_seen"] = stamp()
            site["last_source"] = request.client.host if request.client else ""
            site["report"] = {"sessions": valid_sessions, "services": valid_health, "version": version_in, "policy_revision": revision, "terminals": valid_terminals}
            for device in state["devices"].values():
                if device["site_id"] == gateway_id and not device.get("revoked") and device.get("public_key"):
                    if valid_sessions.get(device["id"], 0) > 0:
                        device.update(last_seen=site["last_seen"], status="conectado")
                    else:
                        device["status"] = "sem túnel"
            return desired_snapshot(state, site)
        return await central.tx(change)

    @app.post("/api/agent/policy")
    async def legacy_policy(request: Request):
        data = await central.body(request, {"status"})
        status = _string(data, "status")
        if len(status.encode()) > 80:
            raise APIError(400, "estado inválido")
        def change(state):
            device_id = _device_id(state, request)
            if not device_id:
                raise APIError(403, "não autorizado")
            device = state["devices"][device_id]
            site = state["sites"].get(device["site_id"])
            if not site:
                raise APIError(403, "cliente removido")
            device.update(last_seen=stamp(), status=status)
            return {"endpoint": site["endpoint"], "host_key": site["host_key"], "services": selected_services(site, device["services"]), "lease_seconds": 300}
        return await central.tx(change)

    from .central_auth import register_routes
    register_routes(app, central)
    return app
