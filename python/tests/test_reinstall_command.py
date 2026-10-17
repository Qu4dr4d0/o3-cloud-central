"""Execute the generated replacement command against an isolated fake firewall."""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from edgehub.central_artifacts import pfsense_command


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('sh'), reason='POSIX fake-root lifecycle')
@pytest.mark.parametrize('scenario', ['installed', 'removed', 'download-fails', 'sha-fails', 'cleanup-fails', 'busy', 'identity-race', 'lock-race', 'enroll-fails'])
def test_replacement_download_cleanup_enrollment_and_races(tmp_path, scenario):
    root = tmp_path / 'root'
    for name in ('bin', 'var/run', 'tmp', 'usr/local/etc/edgehub', 'usr/local/etc/rc.d', 'usr/local/sbin'):
        (root/name).mkdir(parents=True, exist_ok=True)
    config = root/'usr/local/etc/edgehub/config.json'
    if scenario != 'removed': config.write_text('old-identity')
    lock = root/'var/run/edgehub-update.lock'
    if scenario == 'busy':
        lock.mkdir()
        (lock/'other-operation').touch()
    events = root/'events'
    def executable(path, source):
        path.write_text('#!/bin/sh\n'+source+'\n')
        path.chmod(0o700)
    def fake(name, source): executable(root/'bin'/name, source)
    fake('id', 'echo 0')
    fake('uname', 'case "$1" in -s) echo FreeBSD;; -m) echo amd64;; -r) echo 14.0;; esac')
    fake('openssl', 'cat')
    fake('fetch', 'echo download >> "$O3_ROOT/events"; [ "$O3_CASE" != download-fails ] || exit 1; while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; printf fixture > "$1"; exit 0; fi; shift; done; exit 1')
    checksum = hashlib.sha256(b'fixture').hexdigest()
    fake('sha256', '[ "$O3_CASE" != sha-fails ] || { echo invalid; exit 0; }; echo '+checksum)
    fake('tar', 'echo extract >> "$O3_ROOT/events"; cat "$O3_ROOT/helper-template"')
    executable(root/'helper-template', '''[ "$1" = --replace-client ] && [ "$2" = vps_target ] || exit 9
mkdir "$O3_ROOT/var/run/edgehub-update.lock" || exit 1
echo cleanup >> "$O3_ROOT/events"
if [ "$O3_CASE" = cleanup-fails ]; then rmdir "$O3_ROOT/var/run/edgehub-update.lock"; exit 1; fi
rm -f "$O3_ROOT/usr/local/etc/edgehub/config.json"
rmdir "$O3_ROOT/var/run/edgehub-update.lock"
case "$O3_CASE" in
 identity-race) printf other-new-identity > "$O3_ROOT/usr/local/etc/edgehub/config.json";;
 lock-race) mkdir "$O3_ROOT/var/run/edgehub-update.lock"; touch "$O3_ROOT/var/run/edgehub-update.lock/other-operation";;
esac''')
    fake('pkg', '''echo "pkg $1" >> "$O3_ROOT/events"
if [ "$1" = add ]; then
 cp "$O3_ROOT/exe-template" "$O3_ROOT/usr/local/sbin/o3cloudcentral"
 cp "$O3_ROOT/rc-template" "$O3_ROOT/usr/local/etc/rc.d/o3cloudcentral.sh"
fi''')
    executable(root/'exe-template', '''[ "$1" = enroll ] || exit 1
echo enroll >> "$O3_ROOT/events"
[ "$O3_CASE" != enroll-fails ] || exit 1
printf new-identity > "$O3_ROOT/usr/local/etc/edgehub/config.json"''')
    executable(root/'rc-template', 'echo "$1" >> "$O3_ROOT/events"')
    bundle = {'kind':'gateway','url':'https://central.example:8443','ca':'public-fixture','token':'T'*43,'listen':'0.0.0.0:2222'}
    script = shlex.split(pfsense_command(bundle, checksum, replace_site_id='vps_target'))[2]
    # The selected member name remains an absolute pkg member; only filesystem
    # destinations and the temporary installation directory map to this root.
    for source in ('/usr/local/', '/var/run/'):
        script = script.replace(source, str(root)+source)
    script = script.replace('/tmp/edgehub-install.', str(root/'tmp/edgehub-install.'))
    target = root/'run.sh'
    target.write_text(script)
    result = subprocess.run([shutil.which('sh'), str(target)], env={**os.environ,'PATH':str(root/'bin')+':/usr/bin:/bin','O3_ROOT':str(root),'O3_CASE':scenario}, capture_output=True,text=True,timeout=10)
    calls = events.read_text().splitlines()
    assert calls[0] == 'download'
    assert not list((root/'tmp').glob('edgehub-install.*'))
    assert lock.exists() == (scenario in {'busy','lock-race'})
    if scenario in {'installed','removed'}:
        assert result.returncode == 0, result.stderr
        assert calls == ['download','extract','cleanup','pkg add','pkg annotate','enroll','start','status']
        assert config.read_text() == 'new-identity'
    else:
        assert result.returncode != 0
        if scenario in {'download-fails','sha-fails','cleanup-fails','busy'}: assert config.read_text() == 'old-identity'
        if scenario in {'download-fails','sha-fails'}: assert 'extract' not in calls
        if scenario == 'identity-race': assert config.read_text() == 'other-new-identity'
        if scenario in {'busy','lock-race','identity-race','cleanup-fails'}: assert 'pkg add' not in calls
        if scenario == 'enroll-fails': assert not config.exists() and 'start' not in calls
