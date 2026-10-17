"""Root installer for the dedicated Debian/Ubuntu terminal service.

Own paths are distinct from the central and the pfSense agent. The downloaded
payload already contains Python and every runtime dependency: no pip or apt runs.
"""
from __future__ import annotations

import argparse
import asyncio
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from .common import enroll, valid_url

PROGRAM = Path('/opt/o3cloudcentral-agent')
DATA = Path('/var/lib/o3cloudcentral-agent')
UNIT = Path('/etc/systemd/system/o3cloudcentral-agent.service')
CONTROL = Path('/usr/local/bin/o3cloudcentral-agent')
UNINSTALL = Path('/usr/local/sbin/o3cloudcentral-agent-uninstall')
LOCK = Path('/run/o3cloudcentral-agent-install.lock')
SERVICE = 'o3cloudcentral-agent.service'
USER = '_o3cloudagent'
SYSTEM_ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/root','LANG':'C.UTF-8'}
UNIT_MARKER = b'# Managed by O3 Cloud Central terminal installer'

def system(*args, check=True):
    result = subprocess.run(args, env=SYSTEM_ENV, capture_output=True, text=True, timeout=60)
    if check and result.returncode:
        raise RuntimeError('Falha em '+args[0]+': '+result.stderr.strip()[:300])
    return result

def python_env(base: Path) -> dict:
    return {**SYSTEM_ENV,'PYTHONHOME':str(base/'runtime'),'LD_LIBRARY_PATH':str(base/'runtime/lib'),
            'PYTHONPATH':str(base/'app'),'PYTHONNOUSERSITE':'1','PYTHONDONTWRITEBYTECODE':'1'}

def read_existing(config: Path, bundle: dict) -> dict | None:
    if not config.exists() and not config.is_symlink(): return None
    if config.is_symlink() or not config.is_file() or config.stat().st_size > 131072:
        raise ValueError('Configuração local inválida; instalação preservada.')
    current = json.loads(config.read_text())
    if (current.get('kind') != 'agent' or current.get('url') != bundle['url'] or
            not all(isinstance(current.get(k), str) and current[k] for k in ('id','token','private_key','gateway_host_key','gateway_endpoint'))):
        raise ValueError('Já existe outro cadastro neste terminal. Remova o agente antes de trocar de cliente.')
    return current

def validate_environment():
    if sys.platform != 'linux' or os.geteuid() != 0: raise ValueError('Execute como root no Linux.')
    if platform.machine() not in ('x86_64','amd64'): raise ValueError('Este instalador requer Linux amd64 (x86_64).')
    os_release = Path('/etc/os-release').read_text()
    values = dict(line.split('=',1) for line in os_release.splitlines() if '=' in line and not line.startswith('#'))
    if values.get('ID','').strip('"') not in ('debian','ubuntu'): raise ValueError('Distribuição suportada: Debian ou Ubuntu.')
    libc = platform.libc_ver()
    if libc[0] != 'glibc' or tuple(map(int,libc[1].split('.')[:2])) < (2,28): raise ValueError('Este instalador requer glibc 2.28 ou posterior.')
    if not Path('/run/systemd/system').is_dir() or not shutil.which('systemctl',path=SYSTEM_ENV['PATH']): raise ValueError('Este servidor precisa usar systemd.')
    for path in (PROGRAM,DATA,UNIT,CONTROL,UNINSTALL):
        if path.is_symlink(): raise ValueError('Caminho do produto é um link simbólico; instalação cancelada: '+str(path))
    if UNIT.exists() and not UNIT.read_bytes().startswith(UNIT_MARKER): raise ValueError('Unidade de outro produto; instalação preservada.')

def ensure_account():
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    try: grp.getgrnam(USER)
    except KeyError:
        system('groupadd','--system',USER)
        (DATA/'managed-group').touch(mode=0o600)
    try:
        account = pwd.getpwnam(USER)
        if account.pw_uid == 0 or account.pw_dir != str(DATA) or account.pw_shell not in ('/usr/sbin/nologin','/bin/false'):
            raise ValueError('A conta do serviço já existe com outra finalidade.')
    except KeyError:
        system('useradd','--system','--gid',USER,'--home-dir',str(DATA),'--shell','/usr/sbin/nologin','--no-create-home',USER)
        (DATA/'managed-user').touch(mode=0o600)
    return pwd.getpwnam(USER)

def install(bundle_path: Path, payload: Path):
    validate_environment()
    bundle = json.loads(bundle_path.read_text())
    if bundle.get('kind') != 'agent' or not valid_url(bundle.get('url','')) or not bundle.get('ca'):
        raise ValueError('Cadastro do instalador inválido.')
    LOCK.mkdir(mode=0o700)
    stage = None
    backup = None
    switched = False
    saved = {}
    was_running = False
    stopped = False
    try:
        saved = {p:p.read_bytes() if p.exists() else None for p in (UNIT,CONTROL,UNINSTALL)}
        config = DATA/'config.json'
        existing = read_existing(config,bundle)
        stage = Path(tempfile.mkdtemp(prefix='.o3cloudcentral-agent-stage.',dir='/opt'))
        shutil.copytree(payload,stage,dirs_exist_ok=True,symlinks=True)
        stage.chmod(0o755)
        for directory in stage.rglob('*'):
            if directory.is_dir(): directory.chmod(0o755)
        probe = subprocess.run([str(stage/'runtime/bin/python3.12'),'-B','-c','import ssl,asyncssh,aiohttp,httpx,cryptography; print("runtime-ok")'],env=python_env(stage),capture_output=True,text=True,timeout=30)
        if probe.returncode: raise RuntimeError('Runtime incompatível; nenhuma instalação foi substituída: '+probe.stderr[-400:])
        account = ensure_account()
        if not existing:
            # Keep a successfully enrolled identity if a later service step
            # fails, so rerunning this installer does not create a duplicate.
            asyncio.run(enroll(bundle,config))
        os.chown(DATA,account.pw_uid,account.pw_gid)
        DATA.chmod(0o700)
        os.chown(config,account.pw_uid,account.pw_gid)
        config.chmod(0o600)
        current = system('systemctl','is-active','--quiet',SERVICE,check=False)
        if current.returncode not in (0,3,4): raise RuntimeError('Não foi possível confirmar o estado do serviço.')
        was_running = current.returncode == 0
        if UNIT.exists():
            system('systemctl','stop',SERVICE)
            stopped = True
        if PROGRAM.exists():
            backup = Path(tempfile.mkdtemp(prefix='.o3cloudcentral-agent-rollback.',dir='/opt'))
            backup.rmdir()
            os.replace(PROGRAM,backup)
        os.replace(stage,PROGRAM)
        stage = None
        switched = True
        UNIT.write_bytes((PROGRAM/'deploy/o3cloudcentral-agent.service').read_bytes())
        UNIT.chmod(0o644)
        for target,source in ((CONTROL,'control.sh'),(UNINSTALL,'uninstall.sh')):
            target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
            target.write_bytes((PROGRAM/'deploy'/source).read_bytes())
            target.chmod(0o755)
        system('systemctl','daemon-reload')
        system('systemctl','enable','--now',SERVICE)
        for _ in range(20):
            if system('systemctl','is-active','--quiet',SERVICE,check=False).returncode == 0: break
            time.sleep(.25)
        else: raise RuntimeError('O serviço não iniciou. Consulte journalctl -u '+SERVICE)
        if backup: shutil.rmtree(backup); backup=None
        print('O3 Cloud Central instalado neste terminal: '+socket.gethostname())
        print('Estado: sudo o3cloudcentral-agent status')
        print('Remover: sudo o3cloudcentral-agent uninstall')
        print('Todos os comandos: o3cloudcentral-agent help (também disponíveis no painel, em Terminais → Comandos)')
    except BaseException:
        if switched:
            system('systemctl','stop',SERVICE,check=False)
            shutil.rmtree(PROGRAM)
        if backup:
            os.replace(backup,PROGRAM)
            backup = None
        if switched:
            for path,raw in saved.items():
                if raw is None: path.unlink(missing_ok=True)
                else: path.write_bytes(raw);path.chmod(0o644 if path==UNIT else 0o755)
            system('systemctl','daemon-reload',check=False)
        if stopped and was_running: system('systemctl','start',SERVICE,check=False)
        raise
    finally:
        if stage: shutil.rmtree(stage)
        LOCK.rmdir()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--payload',type=Path,required=True)
    args = parser.parse_args()
    try: install(args.bundle,args.payload)
    except Exception as error:
        print('Instalação não concluída: '+str(error),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
