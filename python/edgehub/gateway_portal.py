"""Small HTTPS installation relay, never a proxy to the management router."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
import ssl
import tempfile
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .central_tls import create_tls_contexts

MAX_ENROLLMENT = 128 << 10
MAX_PAGE = 1 << 20
MAX_INSTALLER = (128 << 20) + (64 << 10) + 16
_INSTALL = re.compile(r"/install/windows/[A-Za-z0-9_-]{43}(/installer\.exe)?\Z", re.ASCII)
SECURITY_HEADERS = {
    "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "Connection": "close",
}


def private_client_context(ca: str) -> ssl.SSLContext:
    if not ca:
        raise ValueError("CA obrigatória")
    ctx = ssl.create_default_context(cadata=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def valid_https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        port = parsed.port
        return parsed.scheme == "https" and bool(parsed.hostname) and not any(c.isspace() or c in "\\%*" for c in parsed.hostname) and (port is None or 1 <= port <= 65535) and parsed.username is None and parsed.password is None and parsed.path in ("", "/") and not parsed.query and not parsed.fragment
    except (ValueError, TypeError):
        return False


def portal_ssl_context(config: dict) -> ssl.SSLContext:
    """Validate the existing signed portal key without changing node identity."""
    url = config.get("portal_url", "")
    if not valid_https_origin(url):
        raise ValueError("portal HTTPS não configurado")
    if any(not isinstance(config.get(key), str) or not config[key] for key in ("portal_cert", "portal_key", "ca")):
        raise ValueError("configuração TLS incompleta")
    certs = x509.load_pem_x509_certificates(config["portal_cert"].encode())
    leaf = certs[0]
    private = serialization.load_pem_private_key(config["portal_key"].encode(), None)
    if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
        raise ValueError("o portal requer chave ECDSA P256")
    if leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("chave e certificado incompatíveis")
    now = datetime.now(timezone.utc)
    if not leaf.not_valid_before_utc <= now <= leaf.not_valid_after_utc:
        raise ValueError("certificado expirado")
    try:
        is_ca = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        raise ValueError("certificado de servidor inválido") from None
    if is_ca:
        raise ValueError("certificado de servidor obrigatório")
    # OpenSSL validates the complete chain, EKU, validity and hostname. A
    # MemoryBIO handshake checks the supplied server chain against this CA.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory(prefix="edgehub-tls-") as directory:
        key_path, cert_path = Path(directory) / "key.pem", Path(directory) / "cert.pem"
        key_path.write_text(config["portal_key"], encoding="ascii")
        key_path.chmod(0o600)
        cert_path.write_text(config["portal_cert"], encoding="ascii")
        ctx.load_cert_chain(cert_path, key_path)
    server_in, server_out, client_in, client_out = (ssl.MemoryBIO() for _ in range(4))
    server = ctx.wrap_bio(server_in, server_out, server_side=True)
    client = private_client_context(config["ca"]).wrap_bio(client_in, client_out, server_hostname=urlsplit(url).hostname)
    server_done = client_done = False
    for _ in range(20):
        for stream, incoming, outgoing, which in ((client, server_in, client_out, "client"), (server, client_in, server_out, "server")):
            try:
                stream.do_handshake()
                if which == "client":
                    client_done = True
                else:
                    server_done = True
            except ssl.SSLWantReadError:
                pass
            pending = outgoing.read()
            if pending:
                incoming.write(pending)
        if client_done and server_done:
            return ctx
    raise ValueError("cadeia do certificado inválida")


async def bounded_read(stream: aiohttp.StreamReader, limit: int) -> bytes:
    """read(n) may return only one TCP fragment, not the complete response."""
    chunks, size = [], 0
    async for chunk in stream.iter_chunked(64 << 10):
        size += len(chunk)
        if size > limit:
            raise ValueError("resposta excede o limite")
        chunks.append(chunk)
    return b"".join(chunks)


def portal_route(method: str, raw_path: str) -> tuple[str, bool] | None:
    if any(c in raw_path for c in ("%", "\\", "?", "#")):
        return None
    if method == "POST" and raw_path == "/api/enroll":
        return raw_path, False
    if method != "GET":
        return None
    if raw_path in ("/install/windows.css", "/favicon.ico", "/brand/logo.png"):
        return raw_path, False
    match = _INSTALL.fullmatch(raw_path)
    return (raw_path, bool(match[1])) if match else None


class GatewayPortal:
    def __init__(self, config: dict):
        if config.get("kind") != "gateway" or not valid_https_origin(config.get("url", "")) or not config.get("token"):
            raise ValueError("configuração de gerência inválida")
        self.config = config
        self.ssl = portal_ssl_context(config)
        self.tls_contexts = create_tls_contexts(config["portal_cert"], config["portal_key"])
        self.client: aiohttp.ClientSession | None = None
        self.inflight = 0
        self.runner: web.AppRunner | None = None

    async def setup(self):
        connector = aiohttp.TCPConnector(ssl=private_client_context(self.config["ca"]), limit=32, limit_per_host=32, keepalive_timeout=30)
        self.client = aiohttp.ClientSession(connector=connector, auto_decompress=False, trust_env=False,
                                          timeout=aiohttp.ClientTimeout(total=15, connect=5),
                                          skip_auto_headers={"User-Agent", "Accept-Encoding"})
        app = web.Application(client_max_size=MAX_ENROLLMENT)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        self.runner = web.AppRunner(app, keepalive_timeout=0, handler_cancellation=True,
                                    max_line_size=8190, max_field_size=8190, max_headers=64,
                                    lingering_time=0, shutdown_timeout=2)
        await self.runner.setup()

    async def close(self):
        if self.runner:
            await self.runner.cleanup()
        if self.client:
            await self.client.close()

    def error(self, status: int, text: str) -> web.Response:
        return web.Response(status=status, text=text, headers=SECURITY_HEADERS)

    async def handle(self, request: web.Request) -> web.StreamResponse:
        route = portal_route(request.method, request.raw_path)
        if not route:
            return self.error(404, "recurso não encontrado")
        path, download = route
        if path in ("/install/windows.css", "/favicon.ico", "/brand/logo.png"):
            configured_root = os.environ.get("EDGEHUB_RESOURCE_ROOT")
            root = Path(configured_root) if configured_root else Path(__file__).resolve().parents[2]
            resource, content_type = {
                "/install/windows.css": ("web/install.css", "text/css"),
                "/favicon.ico": ("assets/O3CloudCentral.ico", "image/x-icon"),
                "/brand/logo.png": ("assets/O3CloudCentral.png", "image/png"),
            }[path]
            file = root / resource
            if not configured_root and not file.exists():
                root = Path(__file__).resolve().parents[1]
                file = root / resource
            try:
                payload = file.read_bytes()
            except OSError:
                return self.error(503, "recurso indisponível")
            return web.Response(body=payload, content_type=content_type, headers=SECURITY_HEADERS)
        if self.inflight >= 32:
            return self.error(503, "portal ocupado; tente novamente")
        self.inflight += 1
        try:
            body = None
            if request.method == "POST":
                if request.content_type != "application/json":
                    return self.error(415, "JSON obrigatório")
                if request.content_length and request.content_length > MAX_ENROLLMENT:
                    return self.error(413, "cadastro excede o limite")
                try:
                    body = await asyncio.wait_for(request.read(), 20)
                except (web.HTTPRequestEntityTooLarge, asyncio.TimeoutError):
                    return self.error(413, "cadastro inválido ou muito grande")
                if len(body) > MAX_ENROLLMENT:
                    return self.error(413, "cadastro excede o limite")
            headers = {"Authorization": "Bearer " + self.config["token"], "X-EdgeHub-Gateway": "1"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            limit = MAX_INSTALLER if download else (MAX_ENROLLMENT if body is not None else MAX_PAGE)
            timeout = aiohttp.ClientTimeout(total=300 if download else 15, connect=5, sock_read=30)
            assert self.client is not None
            async with self.client.request(request.method, self.config["url"].rstrip("/") + path,
                                           data=body, headers=headers, timeout=timeout,
                                           allow_redirects=False, max_line_size=8190, max_field_size=8190) as upstream:
                length = upstream.content_length
                if upstream.status < 200 or 300 <= upstream.status < 400 or upstream.status >= 500 or (length is not None and length > limit):
                    return self.error(502, "resposta de instalação indisponível")
                response_headers = dict(SECURITY_HEADERS)
                for key in ("Content-Type", "Content-Disposition"):
                    if key in upstream.headers:
                        response_headers[key] = upstream.headers[key]
                # Bounded API/page responses are validated before committing.
                if not download:
                    payload = await bounded_read(upstream.content, limit)
                    return web.Response(status=upstream.status, body=payload, headers=response_headers)
                response = web.StreamResponse(status=upstream.status, headers=response_headers)
                if length is not None:
                    response.content_length = length
                response.force_close()
                await response.prepare(request)
                size = 0
                async for chunk in upstream.content.iter_chunked(64 << 10):
                    size += len(chunk)
                    if size > limit:
                        request.transport.close()
                        return response
                    await response.write(chunk)
                await response.write_eof()
                return response
        except (aiohttp.ClientError, asyncio.TimeoutError, ssl.SSLError, OSError, ValueError, asyncio.IncompleteReadError):
            return self.error(502, "central temporariamente indisponível para instalações; tente novamente")
        finally:
            self.inflight -= 1


class TrackedHTTP(asyncio.Protocol):
    """Bound headers even across packets; close releases the shared-port slot."""
    def __init__(self, delegate: asyncio.Protocol, closed: asyncio.Future):
        self.delegate, self.closed = delegate, closed
        self.transport = None
        self.headers = bytearray()
        self.header_timer = None

    def connection_made(self, transport):
        self.transport = transport
        self.header_timer = asyncio.get_running_loop().call_later(5, transport.close)
        self.delegate.connection_made(transport)

    def data_received(self, data):
        if self.headers is not None:
            self.headers.extend(data)
            end = self.headers.find(b"\r\n\r\n")
            if (end < 0 and len(self.headers) > 16 << 10) or end > 16 << 10:
                self.transport.close()
                return
            if end >= 0:
                self.headers = None
                self.header_timer.cancel()
        self.delegate.data_received(data)

    def eof_received(self):
        return self.delegate.eof_received()

    def connection_lost(self, exc):
        if self.header_timer:
            self.header_timer.cancel()
        self.delegate.connection_lost(exc)
        if not self.closed.done():
            self.closed.set_result(None)

    def pause_writing(self):
        self.delegate.pause_writing()

    def resume_writing(self):
        self.delegate.resume_writing()
