"""Generated update scripts are executed only against a temporary fake root.

No test invokes pkg, service control or file operations on a real firewall. The
fixed application paths are translated into pytest's directory before execution.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from o3cloudcentral.central_artifacts import PFSENSE_OWNED_PATHS, pfsense_command


def command_script() -> str:
    bundle = {"kind": "gateway-update", "url": "https://central.example:8443", "token": "T" * 43, "ca": "fixture-public-ca"}
    command = pfsense_command(bundle, hashlib.sha256(b"new-package").hexdigest(), update=True)
    return shlex.split(command)[-1]


def test_update_script_covers_runtime_config_registry_and_order():
    script = command_script()
    for path in PFSENSE_OWNED_PATHS:
        assert path in script
    assert 'cp -p /usr/local/etc/o3cloudcentral/config.json "$edge_backup/config.json"' in script
    assert 'pkg create -o "$edge_backup/package" "$edge_previous_name"' in script
    assert 'tar -xpf "$edge_backup/owned.tar" -C /' in script
    assert 'pkg add -f "$edge_previous_pkg"' in script
    assert "rm -rf -- /usr/local/libexec/o3cloudcentral" in script
    assert "/var/db/o3cloudcentral" not in script
    assert script.index('fetch --ca-cert=') < script.index('edge_backup=$(mktemp')
    assert script.index('edge_dirty=1') < script.index('pkg add -f "$edge_tmp/package.pkg"')
    assert script.index('pkg add -f "$edge_tmp/package.pkg"') < script.index('/usr/local/sbin/o3cloudcentral configure-gateway')
    assert script.index('/usr/local/sbin/o3cloudcentral configure-gateway') < script.index('edge_committed=1')
    assert 'mkdir -m 700 "$edge_lock"' in script
    assert 'pkg set -y -n pfSense-pkg-O3CloudCentral:pfSense-pkg-O3CloudCentral' not in script
    assert script.index('! edge_pidfiles_safe stopped') < script.index('if [ -n "$edge_previous_pkg" ]; then')


@pytest.mark.skipif(not shutil.which("sh"), reason="POSIX shell required for generated-script syntax check")
def test_update_script_is_valid_posix_shell(tmp_path):
    path = tmp_path / "update.sh"
    path.write_text(command_script(), encoding="utf-8")
    result = subprocess.run([shutil.which("sh"), "-n", str(path)], text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr


def _write(path: Path, contents: str, *, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755 if executable else 0o600)


FAKE_PKG = r'''import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_ROOT'])
fail = os.environ.get('FAKE_FAIL', '')
args = sys.argv[1:]
registered = root / 'registered'
with (root / 'pkg-actions.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\n')
if args[0] == 'info':
    name = 'pfSense-pkg-O3CloudCentral' if registered.exists() and registered.read_text() in ('new-package', 'renamed-old-package') else 'pfSense-pkg-O3CloudCentral'
    raise SystemExit(0 if registered.exists() and args[-1] == name else 1)
if args[0] == 'set':
    registered.write_text('renamed-old-package' if args[-1] == 'pfSense-pkg-O3CloudCentral' else 'old-package')
    raise SystemExit(0)
if args[0] == 'annotate':
    raise SystemExit(0)
if args[0] == 'query':
    print('pfSense')
    raise SystemExit(0)
if args[0] == 'create':
    if fail == 'backup':
        raise SystemExit(1)
    (pathlib.Path(args[args.index('-o') + 1]) / 'old.pkg').write_bytes(b'old-package')
    raise SystemExit(0)
if args[0] == 'delete':
    registered.unlink(missing_ok=True)
    raise SystemExit(0)
if args[0] != 'add':
    raise SystemExit(2)
package = pathlib.Path(args[-1])
if package.name == 'old.pkg':
    registered.write_text('old-package')
    raise SystemExit(0)
registered.write_text('new-package')
runtime = root / 'usr/local/libexec/o3cloudcentral'
runtime.mkdir(parents=True, exist_ok=True)
(runtime / 'native-python').write_text('new-runtime')
(runtime / 'new-only-file').write_text('new-runtime-only-file')
wrapper = root / 'usr/local/sbin/o3cloudcentral'
wrapper.write_text('#!/bin/sh\n' +
    'if [ "$1" = configure-gateway ]; then printf "new-config" > "' + str(root / 'usr/local/etc/o3cloudcentral/config.json') + '"; [ "$FAKE_FAIL" != configure ] || exit 1; fi\nexit 0\n')
wrapper.chmod(0o755)
canonical = root / 'usr/local/sbin/o3cloudcentral'
canonical.write_text(wrapper.read_text())
canonical.chmod(0o755)
rc = root / 'usr/local/etc/rc.d/o3cloudcentral.sh'
rc.write_text((root / 'new-rc-template').read_text())
rc.chmod(0o755)
new_rc = root / 'usr/local/etc/rc.d/o3cloudcentral.sh'
new_rc.write_text(rc.read_text())
new_rc.chmod(0o755)
policy = root / 'var/db/o3cloudcentral/policy.json'
policy.write_text('new-current-policy')
if fail == 'pkg':
    raise SystemExit(1)
'''


@pytest.mark.skipif(os.name == "nt" or not shutil.which("sh"), reason="Temporary fake-root script execution requires POSIX")
@pytest.mark.parametrize("legacy_go", [False, True])
@pytest.mark.parametrize("failure", ["pkg", "configure", "start", "status", "backup", "sha", "stopfail", "unknownpid", "success"])
def test_update_rollback_against_fake_root(tmp_path, legacy_go, failure):
    root = tmp_path / "fake-root"
    root.mkdir()
    for directory in ("var/run", "var/tmp", "tmp", "var/db/o3cloudcentral", "usr/local/libexec", "usr/local/etc/o3cloudcentral"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    wrapper = root / "usr/local/sbin/o3cloudcentral"
    rc = root / "usr/local/etc/rc.d/o3cloudcentral.sh"
    config = root / "usr/local/etc/o3cloudcentral/config.json"
    runtime = root / "usr/local/libexec/o3cloudcentral"
    original_config = '{"private_key":"fixture-only-key","id":"fixture-gateway"}\n'
    _write(config, original_config)
    _write(wrapper, "#!/bin/sh\n# Original O3CloudCentral wrapper\nexit 0\n", executable=True)
    old_wrapper = wrapper.read_bytes()
    running = root / "running"
    running.touch()
    _write(root / "registered", "old-package")
    _write(root / "var/db/o3cloudcentral/policy.json", "old-policy")
    for owned in PFSENSE_OWNED_PATHS:
        if "o3cloudcentral" in owned:
            continue
        if owned.endswith(("/o3cloudcentral", "/o3cloudcentral.sh")):
            continue
        _write(root / owned, "original: " + owned)
    rc_common = 'case "$1" in\n status) test -f ' + shlex.quote(str(running)) + ';;\n stop) rm -f ' + shlex.quote(str(running)) + ';;\n start) touch ' + shlex.quote(str(running)) + ';;\n *) exit 2;;\nesac\n'
    _write(rc, "#!/bin/sh\n# Original O3CloudCentral rc\n" + rc_common, executable=True)
    old_rc = rc.read_bytes()
    new_rc = '#!/bin/sh\nif [ "$1" = start ] && [ "$FAKE_FAIL" = start ]; then exit 1; fi\nif [ "$1" = status ] && [ "$FAKE_FAIL" = status ]; then exit 1; fi\n'
    new_rc += 'if [ "$1" = start ] && { [ "$FAKE_FAIL" = stopfail ] || [ "$FAKE_FAIL" = unknownpid ]; }; then touch ' + shlex.quote(str(running)) + '; if [ "$FAKE_FAIL" = unknownpid ]; then printf "%s" "$FAKE_UNKNOWN_PID" > ' + shlex.quote(str(root / "var/run/o3cloudcentral-supervisor.pid")) + '; fi; exit 1; fi\n'
    new_rc += 'if [ "$1" = stop ] && [ "$FAKE_FAIL" = stopfail ]; then exit 1; fi\n' + rc_common
    _write(root / "new-rc-template", new_rc)
    if not legacy_go:
        _write(runtime / "native-python", "old-runtime")
        _write(runtime / "old-only-file", "original runtime-only file")
    mock_bin = tmp_path / "mock-bin"
    mock_bin.mkdir()
    _write(mock_bin / "id", '#!/bin/sh\necho 0\n', executable=True)
    _write(mock_bin / "uname", '#!/bin/sh\ncase "$1" in -s) echo FreeBSD;; -m) echo amd64;; -r) echo 14.0;; esac\n', executable=True)
    _write(mock_bin / "pkg_impl.py", FAKE_PKG)
    _write(mock_bin / "pkg", '#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(mock_bin / "pkg_impl.py")) + ' "$@"\n', executable=True)
    _write(mock_bin / "fetch", '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf new-package > "$1"; exit 0; fi; shift; done\nexit 1\n', executable=True)
    checksum = hashlib.sha256(b"new-package").hexdigest()
    _write(mock_bin / "sha256", '#!/bin/sh\nif [ "$FAKE_FAIL" = sha ]; then echo invalid; else echo ' + checksum + '; fi\n', executable=True)
    script = command_script()
    script = script.replace("/usr/local/", str(root / "usr/local") + "/")
    script = script.replace("/var/tmp/", str(root / "var/tmp") + "/")
    script = script.replace("/var/run/", str(root / "var/run") + "/")
    script = script.replace("/tmp/o3cloudcentral-update.", str(root / "tmp/o3cloudcentral-update."))
    # tar's archive member names stay relative, while its root maps to fake-root.
    script = script.replace(" -C / ", " -C " + shlex.quote(str(root)) + " ")
    script = script.replace('"/$edge_path"', '"' + str(root) + '/$edge_path"')
    script_path = tmp_path / "update.sh"
    script_path.write_text(script, encoding="utf-8")
    env = dict(os.environ, PATH=str(mock_bin) + os.pathsep + os.environ["PATH"], FAKE_ROOT=str(root), FAKE_FAIL=failure, FAKE_UNKNOWN_PID=str(os.getpid()))
    result = subprocess.run([shutil.which("sh"), str(script_path)], text=True, capture_output=True, env=env, check=False, timeout=30)
    assert not (root / "var/run/o3cloudcentral-update.lock").exists(), result.stderr
    assert running.exists(), result.stderr
    if failure == "success":
        assert result.returncode == 0, result.stderr
        assert wrapper.read_bytes() != old_wrapper
        assert config.read_text() == "new-config"
        assert (runtime / "native-python").read_text() == "new-runtime"
        assert not list((root / "var/tmp").glob("o3cloudcentral-rollback.*"))
    elif failure in ("stopfail", "unknownpid"):
        assert result.returncode != 0
        # The partially started new process could still use these files. A failed
        # stop or unrelated PID must prohibit *every* restore/restart operation.
        assert wrapper.read_bytes() != old_wrapper, result.stderr
        assert rc.read_bytes() != old_rc, result.stderr
        assert config.read_text() == "new-config"
        assert (runtime / "native-python").read_text() == "new-runtime"
        assert (runtime / "new-only-file").exists()
        assert (root / "registered").read_text() == "new-package"
        actions = [json.loads(line) for line in (root / "pkg-actions.jsonl").read_text().splitlines()]
        assert sum(action[0] == "add" for action in actions) == 1
        assert sum(action[0] == "set" for action in actions) == 1
        assert not any(action[0] == "delete" for action in actions)
        backups = list((root / "var/tmp").glob("o3cloudcentral-rollback.*"))
        assert len(backups) == 1
        assert (backups[0] / "config.json").read_text() == original_config
        assert "backup:" in result.stderr
    else:
        assert result.returncode != 0
        assert wrapper.read_bytes() == old_wrapper, result.stderr
        assert rc.read_bytes() == old_rc, result.stderr
        assert config.read_text() == original_config, result.stderr
        if legacy_go:
            assert not runtime.exists(), result.stderr
        else:
            assert (runtime / "native-python").read_text() == "old-runtime", result.stderr
            assert (runtime / "old-only-file").read_text() == "original runtime-only file"
            assert not (runtime / "new-only-file").exists()
        if failure not in ("sha", "backup"):
            backups = list((root / "var/tmp").glob("o3cloudcentral-rollback.*"))
            assert len(backups) == 1
            assert backups[0].stat().st_mode & 0o777 == 0o700
            assert (backups[0] / "config.json").read_text() == original_config
    expected_policy = "old-policy" if failure in ("backup", "sha") else "new-current-policy"
    assert (root / "var/db/o3cloudcentral/policy.json").read_text() == expected_policy
