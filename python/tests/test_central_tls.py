import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
import pytest

from edgehub.central_tls import (MAX_CLIENT_HELLO, client_hello_ed25519,
                                create_tls_contexts, make_uvicorn_server,
                                select_tls_context)
from edgehub.crypto import initialize_pki, read_ca


def record(payload):
    return b"\x16\x03\x01" + len(payload).to_bytes(2, "big") + payload


def hello(schemes=(0x0403, 0x0807), *, fragmented=False):
    algorithms = b"".join(value.to_bytes(2, "big") for value in schemes)
    extension = b"\x00\x0d" + (len(algorithms) + 2).to_bytes(2, "big") + len(algorithms).to_bytes(2, "big") + algorithms
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x13\x01\x01\x00" + len(extension).to_bytes(2, "big") + extension
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return record(handshake[:3]) + record(handshake[3:]) if fragmented else record(handshake)


@pytest.fixture
def bridge(tmp_path):
    initialize_pki(tmp_path, ["localhost", "127.0.0.1"])
    ca, _, _ = read_ca(tmp_path)
    old_key = ed25519.Ed25519PrivateKey.generate()
    old_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture legacy Ed25519 CA")])
    moment = datetime.now(timezone.utc)
    old_ca = x509.CertificateBuilder().subject_name(old_subject).issuer_name(old_subject).public_key(old_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(moment - timedelta(days=1)).not_valid_after(moment + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(old_key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(old_key.public_key()), critical=False).sign(old_key, None)
    cross = x509.CertificateBuilder().subject_name(ca.subject).issuer_name(old_subject).public_key(ca.public_key()).serial_number(x509.random_serial_number()).not_valid_before(moment - timedelta(hours=1)).not_valid_after(moment + timedelta(days=300)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(old_key.public_key()), critical=False).sign(old_key, None)
    full = (tmp_path / "server.crt").read_bytes() + cross.public_bytes(serialization.Encoding.PEM)
    (tmp_path / "server.crt").write_bytes(full)
    (tmp_path / "legacy.crt").write_bytes(old_ca.public_bytes(serialization.Encoding.PEM))
    return tmp_path, create_tls_contexts(full.decode(), (tmp_path / "server.key").read_text())


def test_client_hello_parser_fragmentation_and_bounds():
    assert client_hello_ed25519(hello()) is True
    assert client_hello_ed25519(hello((0x0403,))) is False
    assert client_hello_ed25519(hello(fragmented=True)) is True
    raw = hello()
    for index in range(len(raw)):
        assert client_hello_ed25519(raw[:index]) is None
    for bad in (b"GET / HTTP/1.1\r\n", b"\x16\x03\x01\xff\xff", b"\x16\x03\x01\x00\x00", b"x" * (MAX_CLIENT_HELLO + 1)):
        with pytest.raises(ValueError):
            client_hello_ed25519(bad)


def test_chain_selection_peeks_without_consuming_and_times_out(bridge):
    _, contexts = bridge
    assert contexts.full is not contexts.standard
    async def check():
        for supported in (True, False):
            sender, receiver = socket.socketpair()
            receiver.setblocking(False)
            try:
                raw = hello() if supported else hello((0x0403,))
                sender.sendall(raw)
                selected = await select_tls_context(receiver, contexts)
                assert selected is (contexts.full if supported else contexts.standard)
                assert receiver.recv(len(raw)) == raw
            finally:
                sender.close()
                receiver.close()
        sender, receiver = socket.socketpair()
        receiver.setblocking(False)
        try:
            with pytest.raises(TimeoutError):
                await select_tls_context(receiver, contexts, timeout=0.02)
        finally:
            sender.close()
            receiver.close()
    asyncio.run(check())


def test_single_ecdsa_chain_requires_no_clienthello_peek(tmp_path):
    initialize_pki(tmp_path, ["localhost"])
    contexts = create_tls_contexts((tmp_path / "server.crt").read_text(), (tmp_path / "server.key").read_text())
    assert contexts.standard is contexts.full


def test_uvicorn_listener_legacy_ca_and_modern_ca_both_validate(bridge, monkeypatch):
    import uvicorn
    import edgehub.central_tls as tls
    folder, contexts = bridge
    selected = []
    select = tls.select_tls_context
    async def spy(raw, available, **kwargs):
        result = await select(raw, available, **kwargs)
        selected.append("full" if result is available.full else "standard")
        return result
    monkeypatch.setattr(tls, "select_tls_context", spy)

    async def application(scope, receive, send):
        assert scope["type"] == "http" and scope["scheme"] == "https"
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"tls":"ok"}'})

    async def request(port, ca):
        context = ssl.create_default_context(cafile=str(ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=context, server_hostname="localhost")
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        await writer.drain()
        response = await reader.read()
        writer.close()
        await writer.wait_closed()
        assert b"200 OK" in response and b'"tls":"ok"' in response

    async def exercise():
        config = uvicorn.Config(application, host="127.0.0.1", port=0,
            ssl_certfile=str(folder / "server.crt"), ssl_keyfile=str(folder / "server.key"),
            http="h11", lifespan="off", access_log=False, log_level="error", timeout_graceful_shutdown=2)
        server = make_uvicorn_server(config, contexts)
        task = asyncio.create_task(server.serve())
        try:
            for _ in range(200):
                if server.started:
                    break
                if task.done():
                    await task
                await asyncio.sleep(0.01)
            assert server.started
            port = server.servers[0].sockets[0].getsockname()[1]
            await request(port, folder / "legacy.crt")
            await request(port, folder / "ca.crt")
            assert selected[:2] == ["full", "full"]
            # OpenSSL's sigalgs switch emulates a Schannel ClientHello which
            # advertises ECDSA but omits Ed25519. Trust is still fully verified.
            if shutil.which("openssl"):
                process = await asyncio.create_subprocess_exec(shutil.which("openssl"), "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-CAfile", str(folder / "ca.crt"), "-verify_return_error", "-verify_hostname", "localhost", "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-quiet", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                output, error = await asyncio.wait_for(process.communicate(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"), 10)
                assert process.returncode == 0, error.decode(errors="replace")
                assert b"200 OK" in output
                assert selected[-1] == "standard"
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 5)
    asyncio.run(exercise())
