"""Exercise native pfSense removal admission without changing a firewall."""
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_service_never_targets_shared_python_or_removes_rcfile():
    xml = ET.parse(ROOT / 'deploy/pfsense/o3cloudcentral.xml').getroot()
    service = xml.find('service')
    assert service.find('rcfile') is None and service.find('executable') is None
    for name in ('startcmd', 'stopcmd', 'custom_php_service_status_command'):
        assert "require_once('/usr/local/pkg/o3cloudcentral.inc')" in service.findtext(name)
    assert xml.findtext('menu/section') == 'Services'
    assert xml.findtext('menu/url') == '/o3cloudcentral_status.php'


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('sh'), reason='Unix isolated process harness')
@pytest.mark.parametrize('scenario', ['remove', 'update', 'wrong-package', 'unknown-option', 'nonroot', 'stale-pid', 'unsafe-file', 'unsafe-ancestor', 'preserve', 'upgrade', 'chroot', 'symlink'])
def test_native_purge_only_admits_verified_gui_removal(tmp_path, scenario):
    worker = tmp_path / 'pfSense-upgrade'
    worker.write_text('#!/bin/sh\n')
    pid = tmp_path / 'GUI.pid'
    pid.write_text('731')
    if scenario == 'symlink':
        pid.unlink()
        pid.symlink_to(worker)
    if scenario == 'stale-pid': pid.write_text('732')
    bins = tmp_path / 'bin'
    bins.mkdir()
    (bins / 'stat').write_text('''#!/bin/sh
case "$*" in *'%u %Lp'*)
 case "$CASE" in unsafe-file) echo '0 666';; *) echo '0 600';; esac;;
 *) echo '1:2:0:600:123';;
esac
''')
    (bins / 'ps').write_text('''#!/bin/sh
case "$*" in *'-p 731 '*)
 uid=0; [ "$CASE" != nonroot ] || uid=1000
 op='-r pfSense-pkg-O3CloudCentral'
 case "$CASE" in update) op='-i pfSense-pkg-O3CloudCentral -f';; wrong-package) op='-r pfSense-pkg-other';; unknown-option) op='-r pfSense-pkg-O3CloudCentral --all';; esac
 printf '1 %s /bin/sh %s -y -l /conf/pkg_log_pfSense-pkg-O3CloudCentral.txt -p /tmp/pfSense-upgrade.sock %s\\n' "$uid" "$WORKER" "$op";;
 *) uid=0; [ "$CASE" != unsafe-ancestor ] || uid=1000; printf '731 %s /bin/sh hook\\n' "$uid";;
esac
''')
    for path in bins.iterdir(): path.chmod(0o700)
    source = (ROOT / 'deploy/pfsense-native-remove.sh').read_text()
    source = source.replace('/var/run/pfSense-upgrade-GUI.pid', str(pid)).replace('/usr/local/sbin/pfSense-upgrade', str(worker))
    target = tmp_path / 'probe.sh'
    target.write_text(source + '\no3c_native_gui_removal\n')
    env = {**os.environ, 'PATH': str(bins) + ':/usr/bin:/bin', 'CASE': scenario, 'WORKER': str(worker), 'PKG_NAME': 'pfSense-pkg-O3CloudCentral'}
    for key in ('PKG_UPGRADE', 'O3C_PRESERVE_STATE', 'O3C_UNINSTALL_ACTIVE', 'PKG_ROOTDIR'): env.pop(key, None)
    if scenario == 'preserve': env['O3C_PRESERVE_STATE'] = '1'
    if scenario == 'upgrade': env['PKG_UPGRADE'] = 'true'
    if scenario == 'chroot': env['PKG_ROOTDIR'] = str(tmp_path)
    result = subprocess.run([shutil.which('sh'), str(target)], env=env, capture_output=True, text=True, timeout=5)
    assert (result.returncode == 0) == (scenario == 'remove'), result.stderr
