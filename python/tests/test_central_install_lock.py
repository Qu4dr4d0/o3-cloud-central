"""Fresh enrollment cannot race a product removal or overwrite an identity."""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from edgehub.central_artifacts import pfsense_command


@pytest.mark.skipif(os.name == "nt" or not shutil.which("sh"), reason="Isolated POSIX shell fixture")
@pytest.mark.parametrize("scenario", ["busy", "existing-config", "dangling-config", "failed-download"])
def test_fresh_install_lock_and_failure_leave_no_partial_identity(tmp_path, scenario):
    root = tmp_path / "fixture"
    for name in ("bin", "var/run", "tmp", "usr/local/etc/edgehub"):
        (root / name).mkdir(parents=True, exist_ok=True)
    lock = root / "var/run/edgehub-update.lock"
    config = root / "usr/local/etc/edgehub/config.json"
    events = root / "events"
    if scenario == "busy":
        lock.mkdir()
    elif scenario == "existing-config":
        config.write_text("preserve-existing-identity")
    elif scenario == "dangling-config":
        config.symlink_to(root / "absent-target")

    def fake(name, body):
        path = root / "bin" / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)

    fake("id", "echo 0")
    fake("uname", 'case "$1" in -s) echo FreeBSD;; -m) echo amd64;; -r) echo 14.0;; esac')
    fake("openssl", "cat >/dev/null")
    fake("fetch", 'echo fetch >> "$O3_EVENTS"; exit 1')
    fake("pkg", 'echo pkg >> "$O3_EVENTS"; exit 99')
    bundle = {"kind": "gateway", "url": "https://central.example:8443", "ca": "fixture-public-ca",
              "token": "T" * 43, "listen": "0.0.0.0:2222"}
    script = shlex.split(pfsense_command(bundle, hashlib.sha256(b"fixture").hexdigest()))[2]
    for source in ("/usr/local/", "/var/run/"):
        script = script.replace(source, str(root) + source)
    script = script.replace("/tmp/edgehub-install.", str(root / "tmp/edgehub-install."))
    target = root / "install.sh"
    target.write_text(script)
    result = subprocess.run([shutil.which("sh"), str(target)], capture_output=True, text=True, timeout=10,
                            env={**os.environ, "PATH": str(root / "bin") + ":/usr/bin:/bin", "O3_EVENTS": str(events)})
    assert result.returncode != 0
    assert lock.exists() == (scenario == "busy")
    assert not list((root / "tmp").glob("edgehub-install.*"))
    assert (events.read_text() if events.exists() else "") == ("fetch\n" if scenario == "failed-download" else "")
    if scenario == "existing-config":
        assert config.read_text() == "preserve-existing-identity"
    elif scenario == "dangling-config":
        assert config.is_symlink()
    else:
        assert not config.exists()
