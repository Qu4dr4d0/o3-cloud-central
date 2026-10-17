"""An imported CA's SKI is authoritative; never guess its digest algorithm."""
from datetime import datetime, timedelta, timezone
import hashlib
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
import pytest

from o3cloudcentral.central_tls import create_tls_contexts
from o3cloudcentral.crypto import (issue_gateway_portal, issue_server,
                            new_gateway_portal_csr)


def _ca_builder(subject, issuer, public, ski, authority):
    moment = datetime.now(timezone.utc)
    return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public).serial_number(x509.random_serial_number()).not_valid_before(moment - timedelta(days=1)).not_valid_after(moment + timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True).add_extension(x509.SubjectKeyIdentifier(ski), critical=False).add_extension(x509.AuthorityKeyIdentifier(authority, None, None), critical=False)


def _verify_strict_handshake(server: ssl.SSLContext, ca_pem: str):
    client_context = ssl.create_default_context(cadata=ca_pem)
    client_context.verify_flags |= ssl.VERIFY_X509_STRICT
    assert client_context.verify_mode == ssl.CERT_REQUIRED
    assert client_context.check_hostname
    client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(client_in, client_out, server_hostname="localhost")
    remote = server.wrap_bio(server_in, server_out, server_side=True)
    client_done = server_done = False
    for _ in range(50):
        try:
            client.do_handshake()
            client_done = True
        except ssl.SSLWantReadError:
            pass
        data = client_out.read()
        if data:
            server_in.write(data)
        try:
            remote.do_handshake()
            server_done = True
        except ssl.SSLWantReadError:
            pass
        data = server_out.read()
        if data:
            client_in.write(data)
        if client_done and server_done:
            return
    pytest.fail("Strict TLS handshake did not complete")


@pytest.fixture
def imported_go_style_ca(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture imported Go ECDSA CA")])
    # An explicit non-SHA1 identifier models Go 1.27's CA identifier convention.
    # The test intentionally treats the certificate value as authoritative.
    public_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ski = hashlib.sha256(public_der).digest()[:20]
    assert ski != x509.SubjectKeyIdentifier.from_public_key(key.public_key()).digest
    ca = _ca_builder(subject, subject, key.public_key(), ski, ski).sign(key, hashes.SHA256())
    legacy = ed25519.Ed25519PrivateKey.generate()
    legacy_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture legacy Ed25519 root")])
    legacy_ski = x509.SubjectKeyIdentifier.from_public_key(legacy.public_key()).digest
    legacy_ca = _ca_builder(legacy_subject, legacy_subject, legacy.public_key(), legacy_ski, legacy_ski).sign(legacy, None)
    cross = _ca_builder(subject, legacy_subject, key.public_key(), ski, legacy_ski).sign(legacy, None)
    modern_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    legacy_pem = legacy_ca.public_bytes(serialization.Encoding.PEM).decode()
    (tmp_path / "ca.crt").write_text(modern_pem + legacy_pem, encoding="ascii")
    (tmp_path / "ca.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "ca.key").chmod(0o600)
    (tmp_path / "ca-cross.crt").write_bytes(cross.public_bytes(serialization.Encoding.PEM))
    return tmp_path, ski, modern_pem, legacy_pem


@pytest.mark.parametrize("kind", ["portal", "central"])
def test_issued_certificate_reuses_imported_ca_ski_and_strict_chain_validates(imported_go_style_ca, kind):
    folder, expected_ski, modern_pem, legacy_pem = imported_go_style_ca
    if kind == "portal":
        csr, private = new_gateway_portal_csr()
        response = issue_gateway_portal(folder, {"endpoint": "localhost:2222", "listen": "0.0.0.0:2222"}, csr)
        certificate = response["portal_cert"]
    else:
        issue_server(folder, ["localhost"])
        certificate = (folder / "server.crt").read_text(encoding="ascii")
        private = (folder / "server.key").read_text(encoding="ascii")
    leaf = x509.load_pem_x509_certificates(certificate.encode())[0]
    assert leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == expected_ski
    contexts = create_tls_contexts(certificate, private)
    # Both the modern root path and the legacy cross-signed path are verified
    # independently, including hostname, EKU, validity and issuer AKI/SKI match.
    _verify_strict_handshake(contexts.full, modern_pem)
    _verify_strict_handshake(contexts.full, legacy_pem)
