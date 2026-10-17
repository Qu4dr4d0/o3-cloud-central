"""Compatible SSH identities, password hashes and locally generated portal keys."""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .common import DEFAULT_GATEWAY_LISTEN, digest, gateway_portal_url, valid_url


def _b64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def hash_admin_password(password: str) -> str:
    salt = os.urandom(16)
    result = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=128 << 20)
    return "scrypt$" + base64.b64encode(salt).decode().rstrip("=") + "$" + base64.b64encode(result).decode().rstrip("=")


def check_admin_password(encoded: str, password: str) -> bool:
    # Persist the mandatory first-login state alongside the salted password.
    if encoded.startswith("bootstrap$"):
        encoded = encoded[len("bootstrap$"):]
    if not encoded.startswith("scrypt$"):
        return bool(re.fullmatch(r"[0-9a-f]{64}", encoded)) and hmac.compare_digest(encoded, digest(password))
    try:
        _, salt, expected = encoded.split("$")
        salt, expected = _b64(salt), _b64(expected)
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=128 << 20)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def new_key() -> tuple[str, str]:
    key = ed25519.Ed25519PrivateKey.generate()
    return (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode(),
        key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + "\n",
    )


def valid_public_key(value: str) -> bool:
    try:
        if not isinstance(value, str) or len(value) > 16384 or len(value.strip().splitlines()) != 1:
            return False
        return isinstance(serialization.load_ssh_public_key(value.strip().encode()), ed25519.Ed25519PublicKey)
    except (ValueError, TypeError):
        return False


def new_gateway_portal_csr() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "O3 Cloud Central pfSense Portal")])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode(), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def _certs(raw: bytes) -> list[x509.Certificate]:
    return x509.load_pem_x509_certificates(raw)


def read_ca(data_dir: str | Path):
    path = Path(data_dir)
    raw = (path / "ca.crt").read_bytes()
    cert = _certs(raw)[0]
    key = serialization.load_pem_private_key((path / "ca.key").read_bytes(), password=None)
    if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("CA e chave nÃ£o correspondem.")
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Certificado nÃ£o Ã© uma autoridade certificadora.")
    return cert, key, raw


def _sign(builder, issuer, key):
    return builder.issuer_name(issuer.subject).sign(key, None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256())


def _issuer_authority_key_identifier(issuer: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """Copy the issuer's actual identifier; different CA tools use different hashes.

    In particular, existing Go-created CAs can have a truncated SHA-256 SKI.
    Recomputing cryptography's default SHA-1 identifier produces a valid signed
    leaf whose AKI cannot match its issuer during OpenSSL path construction.
    """
    try:
        subject_key_identifier = issuer.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key())
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_identifier)


def issue_gateway_portal(data_dir: str | Path, site: dict, csr: str) -> dict:
    portal = gateway_portal_url(site)
    if not valid_url(portal) or not isinstance(csr, str) or len(csr) > 16384 or csr.count("-----BEGIN CERTIFICATE REQUEST-----") != 1 or csr.strip().endswith("-----END CERTIFICATE REQUEST-----") is False:
        raise ValueError("CSR de portal invÃ¡lido.")
    request = x509.load_pem_x509_csr(csr.encode())
    public = request.public_key()
    if not request.is_signature_valid or not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256r1":
        raise ValueError("O portal requer CSR ECDSA P-256 vÃ¡lido.")
    ca, key, _ = read_ca(data_dir)
    now = datetime.now(timezone.utc)
    if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
        raise ValueError("CA fora da validade.")
    host = urlsplit(portal).hostname
    try:
        san = x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        san = x509.DNSName(host)
    builder = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "O3 Cloud Central pfSense Portal")])).public_key(public).serial_number(x509.random_serial_number()).not_valid_before(max(now-timedelta(minutes=5), ca.not_valid_before_utc)).not_valid_after(min(now+timedelta(days=365), ca.not_valid_after_utc)).add_extension(x509.SubjectAlternativeName([san]), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False).add_extension(_issuer_authority_key_identifier(ca), critical=False)
    certificate = _sign(builder, ca, key).public_bytes(serialization.Encoding.PEM)
    cross = Path(data_dir) / "ca-cross.crt"
    if cross.is_file():
        certificate += cross.read_bytes()
    return {"portal_url": portal, "portal_listen": site.get("listen") or DEFAULT_GATEWAY_LISTEN, "portal_cert": certificate.decode()}


def validate_gateway_portal(config: dict) -> None:
    import ssl
    import tempfile
    if not valid_url(config.get("portal_url", "")) or config.get("portal_listen") != (config.get("listen") or DEFAULT_GATEWAY_LISTEN):
        raise ValueError("HTTPS deve compartilhar a escuta SSH do pfSense.")
    cert = _certs(config["portal_cert"].encode())[0]
    key = serialization.load_pem_private_key(config["portal_key"].encode(), password=None)
    public = cert.public_key()
    if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256r1" or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError("Certificado do portal deve ser servidor ECDSA P-256.")
    if public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ValueError("Certificado nÃ£o corresponde Ã  chave local.")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("Certificado fora da validade.")
    host = urlsplit(config["portal_url"]).hostname
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    try:
        valid = ipaddress.ip_address(host) in san.get_values_for_type(x509.IPAddress)
    except ValueError:
        valid = host in san.get_values_for_type(x509.DNSName)
    if not valid or ExtendedKeyUsageOID.SERVER_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
        raise ValueError("Nome ou finalidade do certificado invÃ¡lidos.")
    roots = _certs(config["ca"].encode())
    chain = _certs(config["portal_cert"].encode())[1:] + roots
    issuer = next((candidate for candidate in chain if candidate.subject == cert.issuer), None)
    if issuer is None:
        raise ValueError("Certificado do portal nÃ£o foi emitido pela CA configurada.")
    try:
        cert.verify_directly_issued_by(issuer)
    except InvalidSignature as exc:
        raise ValueError("Certificado nÃ£o foi assinado pela CA configurada.") from exc
    trusted = {root.fingerprint(hashes.SHA256()) for root in roots}
    visited = set()
    while issuer.fingerprint(hashes.SHA256()) not in trusted:
        if not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc:
            raise ValueError("Cadeia de certificados fora da validade.")
        fingerprint = issuer.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            raise ValueError("Cadeia de certificados invÃ¡lida.")
        visited.add(fingerprint)
        parent = next((candidate for candidate in chain if candidate.subject == issuer.issuer and candidate != issuer), None)
        if parent is None or not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Cadeia de certificados nÃ£o confiÃ¡vel.")
        try:
            issuer.verify_directly_issued_by(parent)
        except InvalidSignature as exc:
            raise ValueError("Cadeia de certificados nÃ£o confiÃ¡vel.") from exc
        issuer = parent
    for current in (cert, issuer):
        if not current.not_valid_before_utc <= now < current.not_valid_after_utc:
            raise ValueError("Cadeia de certificados fora da validade.")
    # OpenSSL independently validates the private key / PEM chain syntax.
    with tempfile.TemporaryDirectory(prefix="edgehub-tls-") as tmp:
        cp, kp = Path(tmp)/"cert.pem", Path(tmp)/"key.pem"
        cp.write_text(config["portal_cert"], encoding="ascii")
        kp.write_text(config["portal_key"], encoding="ascii")
        if os.name != "nt":
            kp.chmod(0o600)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cp, kp)


def initialize_pki(data_dir: str | Path, names: list[str]) -> None:
    path = Path(data_dir)
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if any((path / name).exists() for name in ("ca.crt", "ca.key", "server.crt", "server.key")):
        raise ValueError("PKI existente; inicializaÃ§Ã£o nÃ£o sobrescreve chaves.")
    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "O3 Cloud Central CA")])
    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(now+timedelta(days=1825)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    for name, raw in (("ca.crt", cert.public_bytes(serialization.Encoding.PEM)), ("ca-browser.crt", cert.public_bytes(serialization.Encoding.PEM)), ("ca.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
        target = path / name
        with target.open("xb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
    issue_server(path, names)


def issue_server(data_dir: str | Path, names: list[str]) -> None:
    path = Path(data_dir)
    ca, key, _ = read_ca(path)
    now = datetime.now(timezone.utc)
    server = ec.generate_private_key(ec.SECP256R1())
    sans = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    if not sans:
        raise ValueError("Informe nomes ou IPs para o certificado.")
    builder = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "O3 Cloud Central")])).public_key(server.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(hours=1)).not_valid_after(min(now+timedelta(days=365), ca.not_valid_after_utc)).add_extension(x509.SubjectAlternativeName(sans), critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(server.public_key()), critical=False).add_extension(_issuer_authority_key_identifier(ca), critical=False)
    chain = _sign(builder, ca, key).public_bytes(serialization.Encoding.PEM)
    if (path / "ca-cross.crt").exists():
        chain += (path / "ca-cross.crt").read_bytes()
    for name, raw in (("server.crt", chain), ("server.key", server.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))):
        target = path / name
        with target.open("wb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
