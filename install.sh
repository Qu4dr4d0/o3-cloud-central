#!/bin/sh
set -eu
VERSION=0.7.0
REPO=Qu4dr4d0/o3-cloud-central
case "${1:-}" in -h|--help) echo "Uso: sudo sh install.sh --url https://central.exemplo.com:8443 [--upgrade]"; exit 0;; esac
[ "$(id -u)" -eq 0 ] || { echo "Execute com sudo." >&2; exit 1; }
command -v python3 >/dev/null && command -v curl >/dev/null || {
 apt-get update
 DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl ca-certificates
}
work=$(mktemp -d /tmp/o3cloudcentral-install.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
trap 'exit 1' HUP INT TERM
base="https://github.com/$REPO/releases/download/v$VERSION"
curl --fail --location --proto '=https' --proto-redir '=https' "$base/o3-cloud-central-$VERSION.tar.gz" -o "$work/bundle.tar.gz"
curl --fail --location --proto '=https' --proto-redir '=https' "$base/SHA256SUMS" -o "$work/SHA256SUMS"
python3 - "$work" "$VERSION" <<'PY'
import hashlib, pathlib, sys, tarfile
root=pathlib.Path(sys.argv[1]); version=sys.argv[2]
name='o3-cloud-central-'+version+'.tar.gz'
expected=[line.split()[0] for line in (root/'SHA256SUMS').read_text().splitlines() if line.split()[-1]==name]
if len(expected)!=1 or hashlib.sha256((root/'bundle.tar.gz').read_bytes()).hexdigest()!=expected[0]:
    sys.exit('Download inválido: SHA-256 não corresponde.')
with tarfile.open(root/'bundle.tar.gz') as bundle:
    for item in bundle.getmembers():
        path=pathlib.PurePosixPath(item.name)
        if path.is_absolute() or '..' in path.parts or path.parts[0]!='o3-cloud-central-'+version or not (item.isfile() or item.isdir()):
            sys.exit('Caminho inválido no pacote.')
    bundle.extractall(root, filter='data')
PY
python3 "$work/o3-cloud-central-$VERSION/deploy/install-central.py" "$@"
