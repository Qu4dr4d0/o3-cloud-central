from pathlib import Path
import json
import struct

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import pytest

from o3cloudcentral.common import (INSTALLER_MAGIC, embedded_bundle, normalise_terminal_identity,
                            usable_ip, validate_selection)
from o3cloudcentral.crypto import (check_admin_password, hash_admin_password, initialize_pki,
                            issue_gateway_portal, new_gateway_portal_csr, validate_gateway_portal)


def test_password_hash_and_legacy_hash_compatibility():
    from o3cloudcentral.common import digest
    value = hash_admin_password("long-enough-test-password")
    assert check_admin_password(value, "long-enough-test-password")
    assert not check_admin_password(value, "wrong")
    assert check_admin_password(digest("legacy-secret"), "legacy-secret")
    assert not check_admin_password("scrypt$invalid$invalid", "test")


def test_installer_contract_and_small_trailer_validation(tmp_path):
    bundle = {"kind": "agent", "url": "https://gateway.example:2222", "token": "temporary-fixture"}
    raw = json.dumps(bundle).encode()
    target = tmp_path / "O3CloudCentral.exe"
    target.write_bytes(b"MZ-frozen-python-fixture" + raw + struct.pack("<Q8s", len(raw), INSTALLER_MAGIC))
    assert embedded_bundle(target) == bundle
    target.write_bytes(b"MZ")
    with pytest.raises((ValueError, OSError)):
        embedded_bundle(target)


@pytest.mark.parametrize("address", ["127.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.1.2", "::ffff:224.0.0.1", "255.255.255.255", "::", "fe80::1"])
def test_mapped_addresses_cannot_bypass_service_restrictions(address):
    with pytest.raises(ValueError):
        usable_ip(address)


def test_selection_metadata_and_legacy_null_lists():
    assert not validate_selection({"services": None}, [])
    assert not validate_selection({"services": [{"id":"one", "local_port":20000}, {"id":"two", "local_port":20000}]}, ["one", "two"])
    assert normalise_terminal_identity({"hostname": "CAIXA", "local_ip": "10.1.2.3", "agent_version": "0.5.0-lab", "os": "windows"})["hostname"] == "CAIXA"
    assert normalise_terminal_identity({"hostname": "bad\nname"}) is None


def test_portal_certificate_pins_name_key_ca_and_shared_listen(tmp_path):
    initialize_pki(tmp_path, ["localhost", "127.0.0.1"])
    csr, key = new_gateway_portal_csr()
    config = {"listen": "0.0.0.0:2222", "ca": (tmp_path / "ca.crt").read_text(), "portal_key": key}
    config.update(issue_gateway_portal(tmp_path, {"endpoint": "gateway.example:2223", "listen": "0.0.0.0:2222"}, csr))
    validate_gateway_portal(config)
    leaf = x509.load_pem_x509_certificate(config["portal_cert"].encode())
    assert leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    assert leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    with pytest.raises(ValueError):
        validate_gateway_portal({**config, "portal_url": "https://wrong.example:2223"})
    _, other = new_gateway_portal_csr()
    with pytest.raises(ValueError):
        validate_gateway_portal({**config, "portal_key": other})
    other_dir = tmp_path / "other"
    initialize_pki(other_dir, ["localhost"])
    with pytest.raises(ValueError):
        validate_gateway_portal({**config, "ca": (other_dir/"ca.crt").read_text()})
