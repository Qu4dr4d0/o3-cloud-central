#!/bin/sh
# Private runtime: never import modules or shared libraries from user folders.
set -eu
edge_root=/usr/local/libexec/edgehub
exec /usr/bin/env -i PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin HOME=/nonexistent \
 PYTHONHOME="$edge_root/runtime" \
 PYTHONPATH="$edge_root/app:$edge_root/runtime/lib/site-packages" \
 LD_LIBRARY_PATH="$edge_root/runtime/lib" EDGEHUB_RESOURCE_ROOT="$edge_root/app" \
 PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
 AIOHTTP_NO_EXTENSIONS=1 MULTIDICT_NO_EXTENSIONS=1 YARL_NO_EXTENSIONS=1 PROPCACHE_NO_EXTENSIONS=1 \
 "$edge_root/runtime/bin/python3.12" -B -m edgehub "$@"
