#!/bin/sh
# Rehearse package metadata migration in a NEW PRIVATE package database only.
# No installation, removal, package hook, service or product path is touched.
set -eu
umask 077
probe_root=$(mktemp -d /tmp/o3cloudcentral-pkgdb-probe.XXXXXX)
probe_cleanup() {
 case "$probe_root" in
  /tmp/o3cloudcentral-pkgdb-probe.??????) rm -rf -- "$probe_root" ;;
  *) echo 'Unexpected probe directory; preserving it.' >&2 ;;
 esac
}
trap probe_cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -m 700 "$probe_root/db" "$probe_root/cache"
printf '%s\n' 'O3 Cloud Central isolated metadata fixture' > "$probe_root/owned-fixture"
probe_sha=$(sha256 -q "$probe_root/owned-fixture")
printf '{"name":"pfSense-pkg-EdgeHub","version":"0.5.0","origin":"net/edgehub","comment":"Private metadata fixture","desc":"No product installation or hooks","maintainer":"fixture@example.invalid","www":"https://example.invalid","prefix":"%s","arch":"FreeBSD:14:amd64","files":{"%s":"1$%s"}}\n' "$probe_root" "$probe_root/owned-fixture" "$probe_sha" > "$probe_root/manifest.json"
probe_pkg() {
 env PKG_DBDIR="$probe_root/db" PKG_CACHEDIR="$probe_root/cache" pkg "$@"
}
probe_pkg register -M "$probe_root/manifest.json"
[ "$(probe_pkg query -a '%n')" = pfSense-pkg-EdgeHub ]
probe_pkg set -y -n pfSense-pkg-EdgeHub:pfSense-pkg-O3CloudCentral pfSense-pkg-EdgeHub
[ "$(probe_pkg query -a '%n')" = pfSense-pkg-O3CloudCentral ]
[ "$(probe_pkg query '%Fp' pfSense-pkg-O3CloudCentral)" = "$probe_root/owned-fixture" ]
[ "$(sha256 -q "$probe_root/owned-fixture")" = "$probe_sha" ]
probe_pkg set -y -n pfSense-pkg-O3CloudCentral:pfSense-pkg-EdgeHub pfSense-pkg-O3CloudCentral
[ "$(probe_pkg query -a '%n')" = pfSense-pkg-EdgeHub ]
[ "$(probe_pkg query '%Fp' pfSense-pkg-EdgeHub)" = "$probe_root/owned-fixture" ]
[ "$(sha256 -q "$probe_root/owned-fixture")" = "$probe_sha" ]
printf '%s\n' '{"status":"passed","isolated_package_database":true,"rename_and_rollback":true,"file_ownership_preserved":true,"product_installed":false,"system_package_database_changed":false}'
