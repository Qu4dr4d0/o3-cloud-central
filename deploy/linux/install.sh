#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'Execute este instalador como root: sudo sh O3CloudCentral-setup-debian.sh' >&2; exit 1; }
[ "$(uname -s):$(uname -m)" = Linux:x86_64 ] || { echo 'Este instalador requer Debian/Ubuntu Linux amd64 (x86_64).' >&2; exit 1; }
base=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin PYTHONHOME="$base/runtime" LD_LIBRARY_PATH="$base/runtime/lib" PYTHONPATH="$base/app" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 "$base/runtime/bin/python3.12" -B -m edgehub.linux_setup --bundle "$1" --payload "$base"
