"""Linux shell installer delivery using the existing authenticated PF relay."""
import base64
import hashlib
import json
from pathlib import Path
import shlex

LINUX_ARTIFACT = 'O3CloudCentral-linux-amd64.tar.gz'

def installer_prefix(bundle: dict, payload_sha: str) -> bytes:
    encoded = base64.b64encode(json.dumps(bundle,separators=(',',':')).encode()).decode()
    lines = [
        '#!/bin/sh','set -eu',
        '[ "$(id -u)" -eq 0 ] || { echo "Execute como root: sudo sh O3CloudCentral-setup-debian.sh" >&2; exit 1; }',
        '[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || { echo "Este instalador requer Debian/Ubuntu amd64 (x86_64)." >&2; exit 1; }',
        'umask 077','o3tmp=$(mktemp -d /tmp/o3cloudcentral-linux.XXXXXX)',
        'trap \'rm -rf -- "$o3tmp"\' EXIT','trap \'exit 1\' HUP INT TERM',
        'printf %s '+shlex.quote(encoded)+' | base64 -d > "$o3tmp/enrollment.json"',
        'tail -n +PAYLOAD_LINE "$0" > "$o3tmp/payload.tar.gz"',
        'printf "%s  %s\\n" '+shlex.quote(payload_sha)+' "$o3tmp/payload.tar.gz" | sha256sum -c - >/dev/null',
        'mkdir -m 700 "$o3tmp/payload"',
        'tar -xzf "$o3tmp/payload.tar.gz" -C "$o3tmp/payload"',
        '/bin/sh "$o3tmp/payload/deploy/install.sh" "$o3tmp/enrollment.json"',
        'exit 0',
    ]
    return ('\n'.join(lines).replace('PAYLOAD_LINE',str(len(lines)+1))+'\n').encode()

def installer_stream(payload: Path, prefix: bytes):
    yield prefix
    with payload.open('rb') as stream:
        while chunk := stream.read(1 << 20): yield chunk

def bootstrap_command(url: str, ca: str) -> str:
    encoded = base64.b64encode(ca.encode()).decode()
    steps = [
        'set -eu','[ "$(id -u)" -eq 0 ] || { echo "Execute este comando como root ou adicione sudo antes de /bin/sh." >&2; exit 1; }',
        'umask 077','o3tmp=$(mktemp -d /tmp/o3cloudcentral-download.XXXXXX)',
        'trap \'rm -rf -- "$o3tmp"\' EXIT','trap \'exit 1\' HUP INT TERM',
        'printf %s '+shlex.quote(encoded)+' | base64 -d > "$o3tmp/ca.crt"',
        'if command -v curl >/dev/null 2>&1; then curl --proto "=https" --tlsv1.2 --fail --silent --show-error --max-time 180 --cacert "$o3tmp/ca.crt" -o "$o3tmp/install.sh" '+shlex.quote(url)+'; elif command -v wget >/dev/null 2>&1; then wget --https-only --timeout=180 --ca-certificate="$o3tmp/ca.crt" -O "$o3tmp/install.sh" '+shlex.quote(url)+'; else echo "Instale curl ou wget, ou baixe o instalador pelo navegador." >&2; exit 1; fi',
        '/bin/sh "$o3tmp/install.sh"',
    ]
    return '/bin/sh -c '+shlex.quote('; '.join(steps))
