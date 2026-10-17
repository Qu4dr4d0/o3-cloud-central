"""Linux enrollment links remain isolated from Windows and use the PF relay."""
import hashlib
import io
import json
import subprocess
import sys
import tarfile

import pytest

from test_central import AUTH, gateway_enroll, lab, new_service, new_site, post
from o3cloudcentral.central import digest
from o3cloudcentral.linux_artifacts import bootstrap_command, installer_prefix, LINUX_ARTIFACT
from test_central_reusable_links import relay, payload


def test_platform_links_download_enroll_and_revoke_independently(lab):
    client, repository, central = lab
    central.linux_installer.write_bytes(b'fixture-linux-payload')
    site = new_site(client)
    service = new_service(client, site)
    gateway = gateway_enroll(client, site)
    route = f"/api/admin/sites/{site['id']}/install-link"
    windows = post(client, route, {'services':[service['id']]})
    linux = post(client, route, {'services':[service['id']], 'platform':'debian'})
    token = linux['url'].rsplit('/',1)[-1]
    wintoken = windows['url'].rsplit('/',1)[-1]
    assert linux['url'] != windows['url'] and 'command' in linux
    assert repository.read()['tickets'][digest(token)]['platform'] == 'debian'
    page = client.get('/install/windows/'+token, headers=relay(gateway))
    assert page.status_code == 200 and 'Debian' in page.text
    download = client.get('/install/windows/'+token+'/installer.exe', headers=relay(gateway))
    assert download.status_code == 200
    assert 'setup-debian.sh' in download.headers['content-disposition']
    assert download.content.startswith(b'#!/bin/sh\n') and download.content.endswith(b'fixture-linux-payload')
    assert client.get('/install/windows/'+token+'/installer.exe').status_code != 200
    for hostname in ('DEBIAN-01','UBUNTU-02'):
        result = client.post('/api/enroll',json=payload(token,hostname=hostname),headers=relay(gateway))
        assert result.status_code == 200, result.text
    view = client.get('/api/admin/state',auth=AUTH['auth'])
    links = view.json()['sites'][site['id']]['installation_links']
    assert links['debian']['installation_count'] == 2
    assert links['windows']['id'] == windows['id']
    assert token not in view.text and digest(token) not in view.text
    post(client,route,{'services':[service['id']],'platform':'debian'})
    assert client.get('/install/windows/'+token,headers=relay(gateway)).status_code != 200
    assert client.get('/install/windows/'+wintoken,headers=relay(gateway)).status_code == 200
    result = client.request('DELETE',route,json={'platform':'debian'},**AUTH)
    assert result.status_code == 200
    assert len(repository.read()['devices']) == 2
    assert client.get('/install/windows/'+wintoken,headers=relay(gateway)).status_code == 200


def test_missing_linux_artifact_and_invalid_platform_leave_links_unchanged(lab):
    client, repository, central = lab
    site = new_site(client); service = new_service(client,site)
    gateway_enroll(client,site)
    route=f"/api/admin/sites/{site['id']}/install-link"
    before=repository.read()
    assert client.post(route,json={'services':[service['id']],'platform':'debian'},**AUTH).status_code == 503
    assert client.post(route,json={'services':[service['id']],'platform':'arm'},**AUTH).status_code == 400
    assert repository.read() == before


def test_linux_bootstrap_requires_verified_https():
    command=bootstrap_command('https://vpn.example:2222/install/windows/token/installer.exe','public-ca')
    assert '--cacert' in command and '--ca-certificate' in command
    assert '--proto' in command and '--https-only' in command
    assert ' -k ' not in command and 'apt' not in command and 'pip' not in command


@pytest.mark.skipif(sys.platform != 'linux',reason='Native shell extraction check')
def test_self_extract_checks_checksum_before_running_payload(tmp_path):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz') as archive:
        script=b'#!/bin/sh\ncp "$1" "$O3_TEST_BUNDLE"\n'
        member=tarfile.TarInfo('deploy/install.sh');member.size=len(script)
        archive.addfile(member,io.BytesIO(script))
    raw=stream.getvalue();bundle={'kind':'agent','url':'https://vpn.example:2222','ca':'public','token':'fixture'}
    installer=tmp_path/'install.sh'
    prefix=installer_prefix(bundle,hashlib.sha256(raw).hexdigest())
    lines=prefix.splitlines()
    assert f'tail -n +{len(lines)+1}'.encode() in prefix
    # Replace only the root check for this nonprivileged fixture; production
    # script still refuses a regular user before unpacking anything.
    executable=prefix.replace(lines[2],b':')
    import os
    destination=tmp_path/'bundle.json'
    env={**os.environ,'O3_TEST_BUNDLE':str(destination)}
    installer.write_bytes(executable+raw)
    result=subprocess.run(['/bin/sh',str(installer)],env=env,capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(destination.read_text()) == bundle
    destination.unlink();installer.write_bytes(executable+raw[:-1]+bytes([raw[-1]^1]))
    result=subprocess.run(['/bin/sh',str(installer)],env=env,capture_output=True)
    assert result.returncode != 0 and not destination.exists()
