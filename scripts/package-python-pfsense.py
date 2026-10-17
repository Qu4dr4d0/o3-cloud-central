#!/usr/bin/env python3
"""Build O3 Cloud Central's private pfSense runtime without changing its repos.

Only official FreeBSD ABI-14 packages and SHA-256-pinned PyPI pure wheels are
read. No third party installation scripts or package lifecycle hooks execute.
Requires Python 3.14+ (tar zstd support), or an installed zstandard module.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import tarfile
import urllib.request
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
REPO = "https://pkg.freebsd.org/FreeBSD:14:amd64/quarterly/"
PACKAGES = ("python312", "py312-cryptography", "py312-cffi", "py312-pycparser", "expat", "gettext-runtime", "libffi", "mpdecimal", "readline")
WHEELS = {"asyncssh": "2.24.1", "aiohttp": "3.14.5", "multidict": "7.1.0", "frozenlist": "1.8.0", "yarl": "1.25.1", "propcache": "0.5.4", "aiohappyeyeballs": "2.7.1", "aiosignal": "1.4.0", "attrs": "26.1.0", "idna": "3.20", "typing-extensions": "4.16.0", "httpx": "0.28.1", "httpcore": "1.0.9", "anyio": "4.15.1", "certifi": "2026.7.22", "h11": "0.16.0", "sniffio": "1.3.1"}
ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
PFSENSE_PACKAGE_VERSION = "0.6.4"


def file_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def legacy_base32(raw: bytes) -> str:
    result, bits, count = [], 0, 0
    for byte in raw:
        bits |= byte << count
        count += 8
        while count >= 5:
            result.append(ALPHABET[bits & 31])
            bits >>= 5
            count -= 5
    if count:
        result.append(ALPHABET[bits & 31])
    return "".join(result)


def check_catalog_digest(raw: bytes, digest: str):
    if len(digest) == 64 and "$" not in digest:
        actual = file_hash(raw)
    elif digest.startswith("2$"):
        actual = "2$" + legacy_base32(hashlib.blake2b(raw).digest())
    else:
        raise ValueError("unknown official package checksum format: " + digest)
    if actual != digest:
        raise ValueError("FreeBSD package differs from its catalog digest")


def download(url: str, cache: Path, expected_sha: str = "") -> bytes:
    if not url.startswith((REPO, "https://pypi.org/", "https://files.pythonhosted.org/")):
        raise ValueError("unapproved dependency origin")
    key = hashlib.sha256(url.encode()).hexdigest()
    path = cache / key
    if path.exists():
        raw = path.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=90) as response:
            if not response.url.startswith((REPO, "https://pypi.org/", "https://files.pythonhosted.org/")):
                raise ValueError("dependency redirected to an unapproved origin")
            raw = response.read(100 << 20)
            if response.read(1):
                raise ValueError("dependency archive exceeds 100 MiB")
        path.write_bytes(raw)
    if expected_sha and file_hash(raw) != expected_sha:
        raise ValueError("dependency SHA-256 mismatch: " + url)
    return raw


def open_tar(raw: bytes):
    try:
        return tarfile.open(fileobj=io.BytesIO(raw), mode="r:*")
    except tarfile.ReadError:
        if raw[:4] != bytes.fromhex("28b52ffd"):
            raise
        import zstandard
        return tarfile.open(fileobj=io.BytesIO(zstandard.ZstdDecompressor().decompress(raw, max_output_size=512 << 20)), mode="r:")


def runtime_destination(name: str) -> str | None:
    source = name.lstrip("/")
    if source == "usr/local/bin/python3.12":
        return "runtime/bin/python3.12"
    if source.startswith("usr/local/lib/python3.12/"):
        relative = source.removeprefix("usr/local/")
        parts = PurePosixPath(relative).parts
        if any(part in ("test", "tests", "__pycache__", "ensurepip", "idlelib", "tkinter", "config-3.12", "unittest") for part in parts) or source.endswith((".pyc", ".pyo", ".a")):
            return None
        return "runtime/" + relative
    if source.startswith("usr/local/lib/") and "/" not in source.removeprefix("usr/local/lib/") and ".so" in source:
        if source.endswith(".a"):
            return None
        return "runtime/lib/" + source.removeprefix("usr/local/lib/")
    if source.startswith("usr/local/share/licenses/"):
        return "runtime/licenses/" + source.removeprefix("usr/local/share/licenses/")
    return None


def regular_data(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    visited = set()
    while member.issym() or member.islnk():
        if member.name in visited:
            raise ValueError("dependency archive contains circular links")
        visited.add(member.name)
        name = member.linkname
        if not name.startswith("/"):
            name = posixpath.normpath(posixpath.join(posixpath.dirname(member.name), name))
        member = archive.getmember(name)
    if not member.isfile() or member.size > 128 << 20:
        raise ValueError("unexpected dependency archive member")
    return archive.extractfile(member).read()


class Bundle:
    def __init__(self, output: tarfile.TarFile):
        self.output, self.files = output, {}

    def add(self, name: str, raw: bytes, mode=0o644):
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("unsafe bundle path")
        sha = file_hash(raw)
        if name in self.files:
            if self.files[name] != sha:
                raise ValueError("conflicting dependency bundle member: " + name)
            return
        self.files[name] = sha
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(raw), mode, 0
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        self.output.addfile(info, io.BytesIO(raw))


PROBE = '''import sys,ssl,socket,ctypes,hashlib,json,asyncio
import aiohttp,asyncssh,cryptography,cffi
from cryptography.hazmat.primitives.asymmetric import ed25519,ec
from cryptography.hazmat.primitives import serialization
from edgehub.gateway import Gateway
from edgehub.common import load_json, enroll
from edgehub.crypto import new_gateway_portal_csr
from edgehub.cli import parser
key=ed25519.Ed25519PrivateKey.generate(); data=b"O3 Cloud Central native ABI probe"; key.public_key().verify(key.sign(data),data)
ec.generate_private_key(ec.SECP256R1())
asyncssh.generate_private_key("ssh-ed25519")
new_gateway_portal_csr()
print(json.dumps({"python":sys.version.split()[0],"openssl":ssl.OPENSSL_VERSION,"aiohttp":aiohttp.__version__,"asyncssh":asyncssh.__version__,"cryptography":cryptography.__version__,"cffi":cffi.__version__,"gateway_import":True,"signature":True}))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=PROJECT.parent / ".edgehub-python-freebsd-cache")
    parser.add_argument("--output", type=Path, default=PROJECT / "dist/O3CloudCentral-pfsense-runtime.tar.gz")
    parser.add_argument("--lock", type=Path, default=PROJECT / "scripts/python-pfsense-dependencies.json")
    parser.add_argument("--refresh-lock", action="store_true")
    parser.add_argument("--stage-output", type=Path, default=PROJECT / "dist/O3CloudCentral-pfsense-stage.tar.gz")
    args = parser.parse_args()
    args.cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    previous = json.loads(args.lock.read_text()) if args.lock.exists() and not args.refresh_lock else None
    if previous and {wheel["name"]: wheel["version"] for wheel in previous["pure_wheels"]} != WHEELS:
        previous = None
    if previous:
        records = previous["freebsd_packages"]
        wheels = previous["pure_wheels"]
        provenance = {key: value for key, value in previous.items() if key not in ("files", "bundle_sha256")}
    else:
        catalog = download(REPO + "packagesite.pkg", args.cache)
        with open_tar(catalog) as archive:
            packages = {record["name"]: record for record in map(json.loads, archive.extractfile("packagesite.yaml"))}
        records = [{key: packages[name].get(key) for key in ("name", "version", "path", "sum", "arch", "origin", "shlibs_required")} for name in PACKAGES]
        wheels = []
        for name, version in WHEELS.items():
            metadata = json.loads(download(f"https://pypi.org/pypi/{name}/{version}/json", args.cache))
            candidates = [entry for entry in metadata["urls"] if entry["filename"].endswith("-py3-none-any.whl")]
            if len(candidates) != 1:
                raise ValueError("need exactly one pure Python wheel for " + name)
            wheel = candidates[0]
            wheels.append({"name": name, "version": version, "filename": wheel["filename"], "url": wheel["url"], "sha256": wheel["digests"]["sha256"]})
        provenance = {"schema": 1, "abi": "FreeBSD:14:amd64", "python": "3.12", "isolation": "Private relocatable runtime; no package scripts, repository changes or system file replacement", "catalog_url": REPO + "packagesite.pkg", "catalog_sha256": file_hash(catalog), "freebsd_packages": records, "pure_wheels": wheels}
    provenance["product"] = "O3 Cloud Central"
    provenance["application_version"] = "0.6.0"
    provenance["package_version"] = PFSENSE_PACKAGE_VERSION
    with tarfile.open(args.output, "w:gz", format=tarfile.PAX_FORMAT) as output:
        bundle = Bundle(output)
        for record in records:
            if record["arch"] not in ("freebsd:14:x86:64", "freebsd:14:*"):
                raise ValueError("wrong FreeBSD package ABI")
            raw = download(REPO + record["path"], args.cache, record.get("sha256", ""))
            check_catalog_digest(raw, record["sum"])
            record["sha256"] = file_hash(raw)
            with open_tar(raw) as archive:
                for member in archive:
                    destination = runtime_destination(member.name)
                    if destination and (member.isfile() or member.issym() or member.islnk()):
                        data = regular_data(archive, member)
                        bundle.add(destination, data, 0o755 if destination.startswith("runtime/bin/") or ".so" in destination else 0o644)
            print(record["name"], record["version"], record["sha256"], flush=True)
        for wheel in wheels:
            raw = download(wheel["url"], args.cache, wheel["sha256"])
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for info in archive.infolist():
                    if not info.is_dir() and not info.filename.endswith((".pyc", ".pyo")):
                        bundle.add("runtime/lib/site-packages/" + info.filename, archive.read(info))
        for source in sorted((PROJECT / "python/edgehub").glob("*.py")):
            bundle.add("app/edgehub/" + source.name, source.read_bytes())
        for path in ("web/install.css", "assets/O3CloudCentral.ico", "assets/O3CloudCentral.png"):
            bundle.add("app/" + path, (PROJECT / path).read_bytes())
        bundle.add("probe.py", PROBE.encode())
        provenance["files"] = dict(bundle.files)
        bundle.add("runtime/provenance.json", json.dumps(provenance, ensure_ascii=False, indent=2).encode())
    provenance["bundle_sha256"] = file_hash(args.output.read_bytes())
    args.lock.write_text(json.dumps(provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"bundle": str(args.output), "sha256": provenance["bundle_sha256"], "bytes": args.output.stat().st_size, "files": len(provenance["files"])}))
    stage_package(args.output, args.stage_output)


def stage_package(runtime_archive: Path, output_path: Path) -> dict:
    """Prepare pkg-create root, preserving private paths for identity continuity."""
    manifest = {
        "name": "pfSense-pkg-O3CloudCentral", "version": PFSENSE_PACKAGE_VERSION, "origin": "net/o3cloudcentral",
        "comment": "O3 Cloud Central Python TCP access service",
        "desc": "Python SSH forwarding, terminal telemetry and HTTPS enrollment on one TCP port. Private runtime; experimental laboratory package.",
        "maintainer": "o3cloudcentral@example.invalid", "www": "https://example.invalid/o3cloudcentral",
        "prefix": "/usr/local", "arch": "FreeBSD:14:amd64", "files": {},
        "categories": ["net"],
        "scripts": native_package_scripts(),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_path, "w:gz", format=tarfile.PAX_FORMAT) as output:
        bundle = Bundle(output)
        with tarfile.open(runtime_archive, "r:gz") as runtime:
            for member in runtime:
                if not member.isfile() or not member.name.startswith(("runtime/", "app/")):
                    continue
                target = "/usr/local/libexec/edgehub/" + member.name
                raw = runtime.extractfile(member).read()
                bundle.add(target.lstrip("/"), raw, member.mode)
                manifest["files"][target] = "1$" + file_hash(raw)
        sources = {
            "/usr/local/sbin/o3cloudcentral": ("deploy/edgehub-python-wrapper.sh", 0o755),
            "/usr/local/sbin/edgehub": ("deploy/edgehub-python-wrapper.sh", 0o755),
            "/usr/local/sbin/o3cloudcentral-uninstall": ("deploy/o3cloudcentral-uninstall.sh", 0o755),
            "/usr/local/sbin/edgehub-uninstall": ("deploy/edgehub-uninstall.sh", 0o755),
            "/usr/local/etc/rc.d/o3cloudcentral.sh": ("deploy/o3cloudcentral.sh", 0o755),
            "/usr/local/etc/rc.d/edgehub.sh": ("deploy/edgehub.sh", 0o755),
            "/usr/local/etc/newsyslog.conf.d/edgehub.conf": ("deploy/edgehub.newsyslog", 0o644),
            "/usr/local/share/licenses/edgehub/THIRD_PARTY_NOTICES.txt": ("THIRD_PARTY_NOTICES.txt", 0o644),
            "/usr/local/share/pfSense-pkg-O3CloudCentral/info.xml": ("deploy/pfsense/info.xml", 0o644),
            "/usr/local/pkg/o3cloudcentral.xml": ("deploy/pfsense/o3cloudcentral.xml", 0o644),
            "/usr/local/pkg/o3cloudcentral.inc": ("deploy/pfsense/o3cloudcentral.inc", 0o644),
            "/usr/local/www/o3cloudcentral_status.php": ("deploy/pfsense/o3cloudcentral_status.php", 0o644),
            "/usr/local/www/o3cloudcentral-logo.png": ("assets/O3CloudCentral.png", 0o644),
        }
        for target, (relative, mode) in sources.items():
            raw = (PROJECT / relative).read_bytes()
            if relative == "deploy/pfsense/info.xml":
                raw = raw.replace(b"%%PKGVERSION%%", PFSENSE_PACKAGE_VERSION.encode())
            if relative.endswith(".sh") and b"\r" in raw:
                raise ValueError("shell scripts require LF: " + relative)
            bundle.add(target.lstrip("/"), raw, mode)
            manifest["files"][target] = "1$" + file_hash(raw)
        bundle.add("manifest.json", json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode(), 0o600)
    print(json.dumps({"stage": str(output_path), "sha256": file_hash(output_path.read_bytes()), "bytes": output_path.stat().st_size, "package_version": manifest["version"], "files": len(manifest["files"])}))
    return manifest


def native_package_scripts() -> dict[str, str]:
    guard = 'case "${PKG_ROOTDIR:-}" in ""|/) ;; *) exit 0 ;; esac\n'
    framework = '/usr/local/bin/php -f /etc/rc.packages pfSense-pkg-O3CloudCentral '
    # POST-DEINSTALL runs after the installed helper/runtime were unlinked.
    # Embed cleanup and never call pkg while its package database is locked.
    cleanup = (PROJECT / "deploy/edgehub-uninstall.sh").read_text(encoding="utf-8")
    classifier = (PROJECT / "deploy/pfsense-native-remove.sh").read_text(encoding="utf-8")
    return {
        "post-install": guard + framework + 'POST-INSTALL\n',
        "pre-deinstall": guard + framework + 'DEINSTALL\n',
        "post-deinstall": guard + framework + 'POST-DEINSTALL\n' +
            'PKG_NAME=pfSense-pkg-O3CloudCentral\n' + classifier +
            '\no3c_native_gui_removal || exit 0\nset -- --native-cleanup\n' + cleanup,
    }


if __name__ == "__main__":
    main()
