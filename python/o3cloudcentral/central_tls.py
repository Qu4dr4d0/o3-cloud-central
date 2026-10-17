"""TLS chain selection for Windows and pre-migration O3CloudCentral trust roots.

The ECDSA server certificate has an optional Ed25519-signed compatibility
bridge. Schannel must receive the short ECDSA path; old agents require the bridge.
ClientHello is inspected with MSG_PEEK, bounded by time/size/concurrency, before
OpenSSL receives the untouched stream and verifies the complete TLS handshake.
The shared helpers have no Uvicorn dependency and also serve the pfSense portal.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from pathlib import Path
import socket
import ssl
import tempfile
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import SignatureAlgorithmOID

MAX_CLIENT_HELLO = 64 << 10
MAX_RECORD = (16 << 10) + 2048
ED25519 = 0x0807
LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class TLSContexts:
    full: ssl.SSLContext
    standard: ssl.SSLContext


def create_tls_contexts(cert_pem: str, key_pem: str) -> TLSContexts:
    certificates = x509.load_pem_x509_certificates(cert_pem.encode("ascii"))
    if not certificates:
        raise ValueError("Certificado TLS obrigatório.")
    def context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
        result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        result.minimum_version = ssl.TLSVersion.TLSv1_2
        result.set_alpn_protocols(["http/1.1"])
        result.load_cert_chain(cert_path, key_path)
        return result
    with tempfile.TemporaryDirectory(prefix="o3cloudcentral-server-tls-") as directory:
        folder = Path(directory)
        key_path, full_path, short_path = folder / "key.pem", folder / "full.pem", folder / "short.pem"
        key_path.write_text(key_pem, encoding="ascii")
        key_path.chmod(0o600)
        full_path.write_text(cert_pem, encoding="ascii")
        full = context(full_path, key_path)
        standard = full
        if len(certificates) > 1 and certificates[1].signature_algorithm_oid == SignatureAlgorithmOID.ED25519:
            short_path.write_bytes(certificates[0].public_bytes(serialization.Encoding.PEM))
            standard = context(short_path, key_path)
    return TLSContexts(full, standard)


def client_hello_ed25519(raw: bytes) -> bool | None:
    """Return support for Ed25519, None if incomplete, ValueError if malformed.

    TLS record and handshake fragmentation are supported. No contents beyond the
    first bounded ClientHello influence authorization or certificate issuance.
    """
    if len(raw) > MAX_CLIENT_HELLO:
        raise ValueError("ClientHello excede o limite.")
    cursor, handshake = 0, bytearray()
    while cursor < len(raw):
        if len(raw) - cursor < 5:
            return None
        kind, major, minor = raw[cursor:cursor + 3]
        size = int.from_bytes(raw[cursor + 3:cursor + 5], "big")
        if kind != 22 or major != 3 or minor > 4 or not 0 < size <= MAX_RECORD:
            raise ValueError("Registro TLS inicial inválido.")
        if len(raw) - cursor < size + 5:
            return None
        handshake.extend(raw[cursor + 5:cursor + 5 + size])
        cursor += size + 5
        if len(handshake) < 4:
            continue
        if handshake[0] != 1:
            raise ValueError("ClientHello obrigatório.")
        length = int.from_bytes(handshake[1:4], "big")
        if length < 38 or length > MAX_CLIENT_HELLO - 9:
            raise ValueError("Tamanho do ClientHello inválido.")
        if len(handshake) < length + 4:
            continue
        body = memoryview(handshake)[4:4 + length]
        pos = 34  # legacy_version + random
        def take(count):
            nonlocal pos
            if pos + count > len(body):
                raise ValueError("ClientHello truncado.")
            result = body[pos:pos + count]
            pos += count
            return result
        session = int.from_bytes(take(1), "big")
        if session > 32:
            raise ValueError("Sessão TLS inválida.")
        take(session)
        cipher_size = int.from_bytes(take(2), "big")
        if cipher_size < 2 or cipher_size % 2:
            raise ValueError("Cifras TLS inválidas.")
        take(cipher_size)
        compression_size = int.from_bytes(take(1), "big")
        if not compression_size:
            raise ValueError("Compressão TLS inválida.")
        take(compression_size)
        if pos == len(body):
            return False
        extension_size = int.from_bytes(take(2), "big")
        if extension_size != len(body) - pos:
            raise ValueError("Extensões TLS inválidas.")
        schemes = None
        seen = set()
        while pos < len(body):
            kind = int.from_bytes(take(2), "big")
            size = int.from_bytes(take(2), "big")
            value = take(size)
            if kind in seen:
                raise ValueError("Extensão TLS duplicada.")
            seen.add(kind)
            if kind == 13:
                if size < 4:
                    raise ValueError("Algoritmos TLS inválidos.")
                count = int.from_bytes(value[:2], "big")
                if count != size - 2 or count % 2:
                    raise ValueError("Algoritmos TLS inválidos.")
                schemes = [int.from_bytes(value[i:i + 2], "big") for i in range(2, size, 2)]
        return schemes is not None and ED25519 in schemes
    return None


async def select_tls_context(raw: socket.socket, contexts: TLSContexts, *, timeout: float = 5) -> ssl.SSLContext:
    if contexts.full is contexts.standard:
        return contexts.full
    deadline = asyncio.get_running_loop().time() + timeout
    previous = -1
    while asyncio.get_running_loop().time() < deadline:
        try:
            hello = raw.recv(MAX_CLIENT_HELLO, socket.MSG_PEEK)
            if not hello:
                raise ConnectionError("Conexão TLS encerrada.")
            if len(hello) != previous:
                supported = client_hello_ed25519(hello)
                if supported is not None:
                    return contexts.full if supported else contexts.standard
                previous = len(hello)
            if len(hello) >= MAX_CLIENT_HELLO:
                raise ValueError("ClientHello excede o limite.")
        except (BlockingIOError, InterruptedError):
            pass
        await asyncio.sleep(0.01)
    raise TimeoutError("ClientHello não recebido no prazo.")


class TLSListener:
    """Small per-connection TLS adapter around an asyncio protocol factory."""
    def __init__(self, listener: socket.socket, contexts: TLSContexts, protocol_factory: Callable[[], asyncio.Protocol], *, pending_limit: int = 64, on_error: Callable[[], None] | None = None):
        self.listener, self.contexts, self.protocol_factory = listener, contexts, protocol_factory
        self.pending_limit, self.on_error = pending_limit, on_error
        self.tasks: set[asyncio.Task] = set()
        self.closed = False
        self.accept_task = asyncio.create_task(self.accept())

    @property
    def sockets(self):
        return (self.listener,)

    async def connection(self, raw: socket.socket):
        transferred = False
        try:
            context = await select_tls_context(raw, self.contexts)
            await asyncio.get_running_loop().connect_accepted_socket(self.protocol_factory, raw, ssl=context, ssl_handshake_timeout=5, ssl_shutdown_timeout=2)
            transferred = True
        except (ValueError, OSError, TimeoutError, ConnectionError):
            pass
        finally:
            if not transferred:
                raw.close()

    async def accept(self):
        try:
            while not self.closed:
                raw, _ = await asyncio.get_running_loop().sock_accept(self.listener)
                raw.setblocking(False)
                if len(self.tasks) >= self.pending_limit:
                    raw.close()
                    continue
                task = asyncio.create_task(self.connection(raw))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
        except asyncio.CancelledError:
            raise
        except OSError:
            if not self.closed:
                LOG.exception("Falha no listener TLS")
                if self.on_error:
                    self.on_error()

    def close(self):
        self.closed = True
        self.listener.close()
        self.accept_task.cancel()
        for task in self.tasks:
            task.cancel()

    async def wait_closed(self):
        await asyncio.gather(self.accept_task, *tuple(self.tasks), return_exceptions=True)


def make_uvicorn_server(config: Any, contexts: TLSContexts):
    """Keep Uvicorn's HTTP/lifespan/shutdown handling and customize TLS accept."""
    import uvicorn

    class AdaptiveServer(uvicorn.Server):
        async def startup(self, sockets=None):
            if sockets is not None or config.uds or config.fd is not None or config.workers != 1:
                raise ValueError("Este listener TLS requer um único processo e IP/porta explícitos.")
            await self.lifespan.startup()
            if self.lifespan.should_exit:
                self.should_exit = True
                return
            def protocol():
                return config.http_protocol_class(config=config, server_state=self.server_state, app_state=self.lifespan.state, _loop=asyncio.get_running_loop())
            listener = None
            try:
                records = await asyncio.get_running_loop().getaddrinfo(config.host, config.port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
                family, kind, proto, _, address = records[0]
                listener = socket.socket(family, kind, proto)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(address)
                listener.listen(config.backlog)
                listener.setblocking(False)
                self.servers = [TLSListener(listener, contexts, protocol, on_error=lambda: setattr(self, "should_exit", True))]
                self._log_started_message([listener])
                self.started = True
            except BaseException:
                if listener:
                    listener.close()
                await self.lifespan.shutdown()
                raise

        async def shutdown(self, sockets=None):
            listeners = list(self.servers)
            await super().shutdown(sockets=sockets)
            await asyncio.gather(*(listener.wait_closed() for listener in listeners))

    return AdaptiveServer(config)
