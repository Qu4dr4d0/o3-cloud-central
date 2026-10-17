#!/usr/bin/env python3
"""Build a relocatable, offline Linux amd64 terminal payload from pinned sources."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_URL = 'https://github.com/astral-sh/python-build-standalone/releases/download/20260924/cpython-3.12.14%2B20260924-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz'
RUNTIME_SHA = '269b2c99e4db15b242bf01832f4fea1e8f1a664f273cff519393f296e9820b41'
CACHE = ROOT / 'dist/linux-dependency-cache'

def digest(raw): return hashlib.sha256(raw).hexdigest()

def fetch(url, expected=''):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / digest(url.encode())
    if path.exists(): raw = path.read_bytes()
    else:
        req = urllib.request.Request(url,headers={'User-Agent':'O3CloudCentral-build'})
        with urllib.request.urlopen(req, timeout=120) as response:
            if not response.url.startswith(('https://github.com/', 'https://release-assets.githubusercontent.com/', 'https://pypi.org/', 'https://files.pythonhosted.org/')):
                raise ValueError('Unexpected dependency redirect')
            raw = response.read(100 << 20)
            if response.read(1): raise ValueError('Dependency too large')
        path.write_bytes(raw)
    if expected and digest(raw) != expected: raise ValueError('Dependency hash mismatch')
    return raw

def safe_name(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or '\\' in name: raise ValueError('Unsafe archive member')
    return p.as_posix()

def wheel_for(name, version):
    metadata=json.loads(fetch(f'https://pypi.org/pypi/{name}/{version}/json'))
    files=[f for f in metadata['urls'] if f['filename'].endswith('py3-none-any.whl')]
    if not files:
        files=[f for f in metadata['urls'] if f['filename'].endswith('.whl') and
               any(tag in f['filename'] for tag in ('-cp312-cp312-', '-cp311-abi3-', '-cp39-abi3-', '-cp38-abi3-')) and
               'x86_64' in f['filename'] and any(tag in f['filename'] for tag in ('manylinux_2_28','manylinux_2_17','manylinux2014'))]
    if not files: raise ValueError('No compatible wheel for '+name)
    file=sorted(files,key=lambda f:f['filename'])[0]
    return file, fetch(file['url'],file['digests']['sha256'])

def main():
    spec=importlib.util.spec_from_file_location('pfbuild',ROOT/'scripts/package-python-pfsense.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    versions={**module.WHEELS,'cryptography':'50.0.1','cffi':'2.1.1','pycparser':'3.0'}
    output=ROOT/'dist/O3CloudCentral-linux-amd64.tar.gz'
    records=[]; paths=set()
    with tarfile.open(output,'w:gz',format=tarfile.PAX_FORMAT) as archive:
        def add(path,raw,mode=0o644):
            safe_name(path)
            if path in paths: raise ValueError('Duplicate payload member '+path)
            paths.add(path);info=tarfile.TarInfo(path);info.size=len(raw);info.mode=mode;info.mtime=0
            archive.addfile(info,io.BytesIO(raw))
        raw=fetch(RUNTIME_URL,RUNTIME_SHA)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as runtime:
            members={m.name:m for m in runtime.getmembers()}
            for m in members.values():
                name=safe_name(m.name)
                if not name.startswith('python/'): continue
                relative=name[7:]
                if not relative or relative.startswith(('include/','share/man/','lib/python3.12/test/','lib/python3.12/ensurepip/','lib/python3.12/site-packages/pip/')) or relative.endswith(('.pyc','.pyo','.a')): continue
                if m.issym() or m.islnk():
                    target=posixpath.normpath(posixpath.join(posixpath.dirname(name),m.linkname)) if m.issym() else m.linkname
                    safe_name(target)
                    if not target.startswith('python/'): raise ValueError('Runtime link escapes prefix')
                    if m.issym():
                        path='runtime/'+relative
                        paths.add(path);info=tarfile.TarInfo(path);info.type=tarfile.SYMTYPE;info.linkname=m.linkname;info.mode=0o755;info.mtime=0
                        archive.addfile(info)
                        continue
                    original=runtime.getmember(target)
                    if not original.isfile(): continue
                    add('runtime/'+relative,runtime.extractfile(original).read(),original.mode & 0o755)
                elif m.isfile(): add('runtime/'+relative,runtime.extractfile(m).read(),m.mode & 0o755)
        for name,version in versions.items():
            file,raw=wheel_for(name,version)
            records.append({'name':name,'version':version,'file':file['filename'],'url':file['url'],'sha256':digest(raw)})
            with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
                for info in wheel.infolist():
                    if info.is_dir() or info.filename.endswith(('.pyc','.pyo')): continue
                    add('runtime/lib/python3.12/site-packages/'+safe_name(info.filename),wheel.read(info))
            print(name,version,flush=True)
        for source in sorted((ROOT/'python/o3cloudcentral').glob('*.py')): add('app/o3cloudcentral/'+source.name,source.read_bytes())
        for name in ('install.sh','run.sh','control.sh','uninstall.sh','o3cloudcentral-agent.service'):
            add('deploy/'+name,(ROOT/'deploy/linux'/name).read_bytes(),0o755 if name.endswith('.sh') else 0o644)
        add('THIRD_PARTY_NOTICES.txt',(ROOT/'THIRD_PARTY_NOTICES.txt').read_bytes())
        provenance={'architecture':'amd64','python':'3.12.14','glibc_minimum':'2.28','runtime_url':RUNTIME_URL,'runtime_sha256':RUNTIME_SHA,'dependencies':records}
        add('provenance.json',json.dumps(provenance,indent=2).encode())
    provenance['artifact_sha256']=digest(output.read_bytes())
    (ROOT/'scripts/python-linux-dependencies.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps({'artifact':str(output),'sha256':provenance['artifact_sha256'],'bytes':output.stat().st_size,'files':len(paths)}))

if __name__=='__main__': main()
