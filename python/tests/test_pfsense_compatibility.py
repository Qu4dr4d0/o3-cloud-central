"""Platform admission executes before a download, lock or identity change."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

import pytest
from o3cloudcentral.central_artifacts import pfsense_command

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('sh'), reason='POSIX admission harness')
@pytest.mark.parametrize('system,arch,release,accepted', [
    ('FreeBSD','amd64','14.0-CURRENT',True),
    ('FreeBSD','amd64','15.0-CURRENT',True),
    ('FreeBSD','amd64','16.0-CURRENT',True),
    ('FreeBSD','amd64','13.5-RELEASE',False),
    ('FreeBSD','amd64','17.0-CURRENT',False),
    ('FreeBSD','aarch64','16.0-CURRENT',False),
    ('Linux','amd64','16.0',False),
])
def test_platform_guard_precedes_all_changes(tmp_path,system,arch,release,accepted):
    bundle={'kind':'gateway','url':'https://central.example:8443','token':'T'*43,'ca':'fixture'}
    script=shlex.split(pfsense_command(bundle,hashlib.sha256(b'fixture').hexdigest()))[2]
    guard=script.split('; umask 077',1)[0]
    for name,body in {'id':'echo 0','uname':'case "$1" in -s) echo '+shlex.quote(system)+';; -m) echo '+shlex.quote(arch)+';; -r) echo '+shlex.quote(release)+';; esac'}.items():
        path=tmp_path/name;path.write_text('#!/bin/sh\n'+body+'\n');path.chmod(0o755)
    result=subprocess.run([shutil.which('sh'),'-c',guard],env={**os.environ,'PATH':str(tmp_path)+':/usr/bin:/bin'},capture_output=True,text=True,timeout=5)
    assert (result.returncode==0)==accepted,result.stderr


def test_compatibility_libraries_are_pinned_and_private():
    stage=ROOT/'dist/O3CloudCentral-pfsense-stage.tar.gz'
    if not stage.exists(): pytest.skip('release staging artifact not present')
    with tarfile.open(stage) as archive:
        manifest=json.load(archive.extractfile('manifest.json'))
        assert manifest['abi']=='FreeBSD:*:amd64'
        assert manifest['arch']=='freebsd:*:x86:64'
        assert manifest['annotations']['FreeBSD_version']=='1400000'
        assert 'FreeBSD:amd64:16.*' in manifest['scripts']['pre-install']
        base='usr/local/libexec/o3cloudcentral/'
        provenance=json.load(archive.extractfile(base+'runtime/provenance.json'))
        assert provenance['supported_freebsd_majors']==[14,15,16]
        assert len(provenance['compatibility_package']['sha256'])==64
        for name in ('libssl.so.30','libcrypto.so.30','libutil.so.9','libmd.so.6'):
            member=base+'runtime/lib/'+name
            assert archive.extractfile(member).read()[:6]==b'\x7fELF\x02\x01'
            assert '/'+member in manifest['files']
        assert not any(name.startswith(('lib/','usr/lib/','usr/local/lib/compat/')) for name in archive.getnames())
