"""Package boundaries and Unix uninstaller ownership, without product installs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import subprocess
import sys
import tarfile

import pytest

PROJECT = Path(__file__).resolve().parents[2]


def test_final_stage_contains_only_private_product_paths():
    stage = PROJECT / "dist/O3CloudCentral-pfsense-stage.tar.gz"
    if not stage.exists():
        pytest.skip("native staging artifact is produced by the release build")
    with tarfile.open(stage, "r:gz") as archive:
        manifest = json.load(archive.extractfile("manifest.json"))
        assert manifest["name"] == "pfSense-pkg-O3CloudCentral"
        assert manifest["version"] == "0.7.2"
        assert manifest['categories'] == ['net']
        assert set(manifest['scripts']) == {'pre-install', 'post-install', 'pre-deinstall', 'post-deinstall'}
        assert 'set -- --native-cleanup' in manifest['scripts']['post-deinstall']
        assert 'o3c_native_gui_removal || exit 0' in manifest['scripts']['post-deinstall']
        fixed = {"/usr/local/sbin/o3cloudcentral", "/usr/local/sbin/o3cloudcentral-uninstall", "/usr/local/etc/rc.d/o3cloudcentral.sh", "/usr/local/sbin/o3cloudcentral", "/usr/local/sbin/o3cloudcentral-uninstall", "/usr/local/etc/rc.d/o3cloudcentral.sh", "/usr/local/etc/newsyslog.conf.d/o3cloudcentral.conf", "/usr/local/share/licenses/o3cloudcentral/THIRD_PARTY_NOTICES.txt"}
        fixed.update({'/usr/local/share/pfSense-pkg-O3CloudCentral/info.xml', '/usr/local/pkg/o3cloudcentral.xml', '/usr/local/pkg/o3cloudcentral.inc', '/usr/local/www/o3cloudcentral_status.php', '/usr/local/www/o3cloudcentral-logo.png'})
        for path, expected in manifest["files"].items():
            assert path in fixed or path.startswith("/usr/local/libexec/o3cloudcentral/")
            assert "/../" not in path and "\\" not in path
            member = archive.getmember(path.lstrip("/"))
            assert member.isfile() and not member.issym() and not member.islnk()
            raw = archive.extractfile(member).read()
            assert expected == "1$" + hashlib.sha256(raw).hexdigest()
        wrapper = archive.extractfile("usr/local/sbin/o3cloudcentral").read().decode()
        assert '/usr/bin/env -i' in wrapper and '-B -m o3cloudcentral "$@"' in wrapper
        assert 'PYTHONNOUSERSITE=1' in wrapper
        assert archive.getmember("usr/local/libexec/o3cloudcentral/runtime/bin/python3.12").mode == 0o755
        assert "/usr/local/etc/o3cloudcentral/config.json" not in manifest["files"]
        assert "/var/db/o3cloudcentral/policy.json" not in manifest["files"]
        assert "usr/local/libexec/o3cloudcentral/probe.py" not in archive.getnames()
        assert "usr/local/libexec/o3cloudcentral/app/assets/O3CloudCentral.ico" in archive.getnames()
        assert "usr/local/libexec/o3cloudcentral/app/assets/O3CloudCentral.png" in archive.getnames()
        canonical_rc = archive.extractfile("usr/local/etc/rc.d/o3cloudcentral.sh").read().decode()
        assert 'name="o3cloudcentral"' in canonical_rc and '/var/run/o3cloudcentral-supervisor.pid' in canonical_rc


@pytest.mark.skipif(os.name == "nt" or not shutil.which("sh"), reason="isolated shell harness runs on Unix/FreeBSD")
@pytest.mark.parametrize("scenario", [
    "python", "go", "canonical-wrapper", "canonical-supervisor", "dead-child-supervisor",
    "preexisting-user", "symlink-private-root", "missing-packages", "self-removal", "orphan-child", "idempotent",
    "unrelated-pid", "invalid-pid", "symlink-pid", "ps-error", "ps-empty", "pgrep-error", "update-lock",
    "pid-reused", "unkillable", "signal-fails", "pkg-error", "pkg-keeps-registration", "pkg-info-error",
    "cleanup-keeps-config", "cleanup-fails",
    "stop-only", "native-cleanup", "native-upgrade", "native-preserve",
    "replace-matching", "replace-other", "replace-invalid", "replace-symlink", "replace-missing",
])
def test_uninstaller_removes_only_verified_product_resources(tmp_path, scenario):
    root = tmp_path.resolve()
    bin_dir = root / "bin"
    bin_dir.mkdir()
    events, stopped = root / "events", root / "stopped"

    def put(name, content="O3CloudCentral", mode=0o600):
        path = root / name.lstrip("/")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    config = put("/usr/local/etc/o3cloudcentral/config.json")
    cache = put("/var/db/o3cloudcentral/policy.json")
    put("/usr/local/sbin/o3cloudcentral")
    canonical_exe = put("/usr/local/sbin/o3cloudcentral")
    canonical_uninstall = put("/usr/local/sbin/o3cloudcentral-uninstall")
    canonical_rc = put("/usr/local/etc/rc.d/o3cloudcentral.sh")
    native_page = put('/usr/local/www/o3cloudcentral_status.php')
    native_xml = put('/usr/local/pkg/o3cloudcentral.xml')
    native_info = put('/usr/local/share/pfSense-pkg-O3CloudCentral/info.xml')
    put("/usr/local/etc/rc.d/o3cloudcentral.sh")
    runtime_file = put("/usr/local/libexec/o3cloudcentral/runtime/bin/python3.12")
    unrelated = put("/etc/config.xml", "preserve pfSense")
    other_service = put("/var/log/sshd.log", "preserve SSH")
    external_target = put("/another-app/keep.txt", "preserve other application")
    if scenario in {'replace-matching', 'replace-other'}:
        config.write_text(json.dumps({'kind':'gateway', 'id':'vps_target' if scenario == 'replace-matching' else 'vps_other'}))
    if scenario == 'replace-symlink':
        config.unlink()
        config.symlink_to(external_target)
    if scenario == 'replace-missing': config.unlink()
    php_check = 'import os,json,sys;from pathlib import Path;c=json.loads((Path(os.environ["EDGE_ROOT"])/"usr/local/etc/o3cloudcentral/config.json").read_text());sys.exit(0 if c.get("kind")=="gateway" and c.get("id")==sys.argv[-1] else 1)'
    put('/usr/local/bin/php', '#!/bin/sh\nexec '+shlex.quote(sys.executable)+' -c '+shlex.quote(php_check)+' "$@"\n', 0o700)
    if scenario == "symlink-private-root":
        private = root / "usr/local/libexec/o3cloudcentral"
        # The verified fixture root is the only recursive filesystem target.
        assert private.resolve().is_relative_to(root)
        shutil.rmtree(private)
        private.symlink_to(external_target.parent, target_is_directory=True)
    if scenario != "preexisting-user":
        put("/usr/local/etc/o3cloudcentral/managed-user", "")
        put("/usr/local/etc/o3cloudcentral/managed-group", "")
    child_pidfile = put("/var/run/o3cloudcentral.pid", "202")
    child = "/usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json" if scenario == "go" else "/usr/local/libexec/o3cloudcentral/runtime/bin/python3.12 -B -m o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"
    if scenario == "canonical-wrapper":
        child = "/usr/local/sbin/o3cloudcentral gateway --config /usr/local/etc/o3cloudcentral/config.json"
    supervisor = ""
    if scenario in ("canonical-supervisor", "dead-child-supervisor"):
        put("/var/run/o3cloudcentral-supervisor.pid", "201")
        supervisor = "daemon: /usr/local/sbin/" + ("o3cloudcentral" if scenario == "dead-child-supervisor" else "o3cloudcentral") + "[202] (daemon)"
    if scenario == "unrelated-pid":
        child = "/usr/local/bin/python3.12 -B -m another_app --config elsewhere.json"
    if scenario == "invalid-pid":
        child_pidfile.write_text("1")
    if scenario == "symlink-pid":
        child_pidfile.unlink()
        child_pidfile.symlink_to(put("/another-app/pid", "202"))
    if scenario == "orphan-child":
        child_pidfile.unlink()
    lock = root / "var/run/o3cloudcentral-update.lock"
    if scenario == "update-lock":
        lock.mkdir()
        (lock / "another-operation").write_text("preserve lock")
    for prefix in ("/usr/local/", "/var/run/", "/var/log/", "/var/etc/", "/var/db/"):
        child = child.replace(prefix, str(root) + prefix)
        supervisor = supervisor.replace(prefix, str(root) + prefix)
    put("/bin/id", "#!/bin/sh\necho 0\n", 0o700)
    put("/bin/ps", '''#!/bin/sh
[ "$EDGE_CASE" != ps-error ] || exit 2
[ "$EDGE_CASE" != ps-empty ] || exit 0
case "$*" in *"-p 201 "*) p=201; a=$EDGE_SUPERVISOR ;; *) p=202; a=$EDGE_CHILD ;; esac
[ ! -f "$EDGE_STOPPED.$p" ] || exit 1
[ -n "$a" ] || exit 1
if [ "$p" = 202 ]; then
 [ "$EDGE_CASE" != dead-child-supervisor ] || exit 1
 if [ "$EDGE_CASE" = pid-reused ]; then
  n=0; [ ! -f "$EDGE_ROOT/ps-count" ] || n=$(cat "$EDGE_ROOT/ps-count")
  n=$((n + 1)); printf '%s' "$n" > "$EDGE_ROOT/ps-count"
  [ "$n" -le 2 ] || a='/usr/sbin/sshd -D'
 fi
fi
printf '%s\\n' "$a"
''', 0o700)
    put("/bin/pgrep", '''#!/bin/sh
[ "$EDGE_CASE" != pgrep-error ] || exit 2
[ "$1" = -f ] || exit 1
case "$2" in *daemon:*)
 [ -n "$EDGE_SUPERVISOR" ] && [ ! -f "$EDGE_STOPPED.201" ] || exit 1
 echo 201 ;;
 *)
 [ "$EDGE_CASE" != unrelated-pid ] || exit 1
 [ "$EDGE_CASE" != dead-child-supervisor ] || exit 1
 [ ! -f "$EDGE_STOPPED.202" ] || exit 1
 echo 202 ;;
esac
''', 0o700)
    put("/bin/sleep", "#!/bin/sh\nexit 0\n", 0o700)
    if scenario != "missing-packages":
        put("/pkg-pfSense-pkg-O3CloudCentral", "installed")
        put("/pkg-pfSense-pkg-O3CloudCentral", "installed")
    put("/bin/pkg", '''#!/bin/sh
printf 'pkg %s\\n' "$*" >> "$EDGE_EVENTS"
for a in "$@"; do name=$a; done
if [ "$1" = info ]; then
 [ "$EDGE_CASE" != pkg-info-error ] || exit 70
 [ -f "$EDGE_ROOT/pkg-$name" ]; exit $?
fi
[ "$EDGE_CASE" != pkg-error ] || exit 70
[ "$EDGE_CASE" = pkg-keeps-registration ] || rm -f "$EDGE_ROOT/pkg-$name"
[ "$EDGE_CASE" != self-removal ] || rm -f "$EDGE_SCRIPT"
exit 0
''', 0o700)
    put("/bin/rm", '''#!/bin/sh
for a in "$@"; do
 if [ "$a" = "$EDGE_ROOT/usr/local/etc/o3cloudcentral" ]; then
  [ "$EDGE_CASE" != cleanup-keeps-config ] || exit 0
  [ "$EDGE_CASE" != cleanup-fails ] || exit 1
 fi
done
exec /bin/rm "$@"
''', 0o700)
    put("/bin/pw", '''#!/bin/sh
printf 'pw %s\n' "$*" >> "$EDGE_EVENTS"
case "$1:$2" in
 usershow:-a) exit 0 ;;
 usershow:*) echo '_o3cloudcentral:*:1001:2000::0:0:User:/nonexistent:/usr/sbin/nologin' ;;
 groupshow:*) echo '_o3cloudcentral:*:2000:' ;;
esac
''', 0o700)
    script = (PROJECT / "deploy/o3cloudcentral-uninstall.sh").read_text()
    for prefix in ("/usr/local/", "/var/run/", "/var/log/", "/var/etc/", "/var/db/"):
        script = script.replace(prefix, str(root) + prefix)
    # Prevent all real signals even if the ownership test itself regresses.
    script = script.replace("set -eu", '''set -eu
kill() {
 printf 'kill %s\\n' "$*" >> "$EDGE_EVENTS"
 [ "$EDGE_CASE" != signal-fails ] || return 1
 [ "$EDGE_CASE" != unkillable ] || return 0
 : > "$EDGE_STOPPED.$2"
}''', 1)
    target = put("/uninstall-test.sh", script, 0o700)
    env = {**os.environ, "PATH": str(bin_dir) + ":/usr/bin:/bin", "EDGE_CHILD": child,
           "EDGE_SUPERVISOR": supervisor, "EDGE_EVENTS": str(events), "EDGE_STOPPED": str(stopped),
           "EDGE_CASE": scenario, "EDGE_ROOT": str(root), "EDGE_SCRIPT": str(target)}
    if scenario == 'native-cleanup':
        # pkg unlinks its manifest files first; it prunes directories after the hook.
        runtime_file.unlink()
        native_info.unlink()
    args = ['--stop-only'] if scenario == 'stop-only' else ['--native-cleanup'] if scenario.startswith('native-') else []
    if scenario.startswith('replace-'): args = ['--replace-client', 'vps_target']
    if scenario == 'native-upgrade': env['PKG_UPGRADE'] = 'true'
    if scenario == 'native-preserve': env['O3C_PRESERVE_STATE'] = '1'
    result = subprocess.run([shutil.which("sh"), str(target), *args], capture_output=True, text=True, timeout=10,
                            env=env)
    recorded = events.read_text() if events.exists() else ""
    if scenario in {'stop-only', 'native-upgrade', 'native-preserve'}:
        assert result.returncode == 0, result.stderr
        assert config.exists() and cache.exists() and native_page.exists() and native_info.exists()
        assert 'pkg ' not in recorded and 'pw userdel' not in recorded
        assert not lock.exists()
        assert unrelated.read_text() == 'preserve pfSense'
        if scenario != 'stop-only': assert 'kill ' not in recorded
        return
    early_failures = {"unrelated-pid", "invalid-pid", "symlink-pid", "ps-error", "ps-empty", "pgrep-error", "update-lock", 'replace-other', 'replace-invalid', 'replace-symlink'}
    failures = early_failures | {"pid-reused", "unkillable", "signal-fails", "pkg-error", "pkg-keeps-registration", "pkg-info-error", "cleanup-keeps-config", "cleanup-fails"}
    if scenario in failures:
        assert result.returncode != 0
        assert config.exists() and cache.exists()
        assert "removido deste pfSense" not in result.stdout
        if scenario in early_failures:
            assert "kill" not in recorded and "pkg delete" not in recorded
        if scenario in {"pid-reused", "unkillable", "signal-fails"}:
            assert "pkg delete" not in recorded
        if scenario == "pid-reused":
            assert "kill" not in recorded  # Reused PID is detected immediately before signalling.
    else:
        assert result.returncode == 0, result.stderr
        assert ("kill -TERM 201" if scenario in ("canonical-supervisor", "dead-child-supervisor") else "kill -TERM 202") in recorded
        if scenario == "dead-child-supervisor":
            assert "kill -TERM 202" not in recorded  # Actual PF2 failure: live daemon, dead child.
        assert not config.exists() and not cache.exists()
        assert (root / "usr/local/libexec/o3cloudcentral").exists() == (scenario == 'native-cleanup')
        if scenario == 'native-cleanup': assert not runtime_file.exists()  # pkg owns the final directory pruning.
        assert not canonical_exe.exists() and not canonical_uninstall.exists() and not canonical_rc.exists()
        assert not native_page.exists() and not native_xml.exists() and not native_info.exists()
        assert ("pkg delete -y -f pfSense-pkg-O3CloudCentral" in recorded) == (scenario not in {"missing-packages", 'native-cleanup'})
        assert ("pkg delete -y -f pfSense-pkg-O3CloudCentral" in recorded) == (scenario not in {"missing-packages", 'native-cleanup'})
        if scenario == 'native-cleanup': assert 'pkg ' not in recorded
        assert ("pw userdel _o3cloudcentral" in recorded) == (scenario != "preexisting-user")
        assert "removido deste pfSense" in result.stdout
        if scenario == "self-removal":
            assert not target.exists()  # pkg unlinks the executing script, cleanup still finishes.
        if scenario == "idempotent":
            repeated = subprocess.run([shutil.which("sh"), str(target)], capture_output=True, text=True, timeout=10, env=env)
            assert repeated.returncode == 0, repeated.stderr
            assert "removido deste pfSense" in repeated.stdout
    assert lock.exists() == (scenario == "update-lock")
    assert unrelated.read_text() == "preserve pfSense"
    assert other_service.read_text() == "preserve SSH"
    assert external_target.read_text() == "preserve other application"
