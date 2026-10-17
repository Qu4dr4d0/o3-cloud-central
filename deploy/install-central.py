#!/usr/bin/env python3
"""Install the central on a dedicated Ubuntu VM; never replace unknown state."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/opt/o3cloudcentral")
DATA = Path("/var/lib/o3cloudcentral")
MARKER = Path("/etc/o3cloudcentral-install.json")
DSN = "mysql+pymysql://o3cloudcentral@localhost/o3cloudcentral?unix_socket=/run/mysqld/mysqld.sock"

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def write(path, value, mode=0o600):
    path = Path(path)
    temporary = path.with_name(path.name + ".new")
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, mode)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)

def link(path, target):
    temporary = Path(str(path) + ".new")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, path)

def sql(query):
    return subprocess.check_output(["mariadb", "--batch", "--skip-column-names", "-e", query], text=True).strip()

def origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or not re.fullmatch(r"[A-Za-z0-9.:-]+", parsed.hostname)):
        raise ValueError("Use uma URL HTTPS sem caminho: https://central.exemplo.com:8443")
    port = parsed.port or 443
    if not 1024 <= port <= 65535:
        raise ValueError("Use uma porta entre 1024 e 65535, por exemplo 8443.")
    return value.rstrip("/"), parsed.hostname, port

def main():
    parser = argparse.ArgumentParser(description="Instala O3 Cloud Central com MariaDB local no Ubuntu 24.04/26.04 amd64.")
    parser.add_argument("--url", required=True, help="URL HTTPS estável alcançável pelos pfSenses e administradores")
    parser.add_argument("--upgrade", action="store_true", help="Atualiza uma instalação criada por este instalador, preservando banco e identidade")
    parser.add_argument("--prepare-only", action="store_true", help="Prepara imagem de teste sem iniciar a central; não é o modo normal de instalação")
    args = parser.parse_args()
    url, host, port = origin(args.url)
    if os.geteuid() != 0:
        parser.error("Execute com sudo.")
    system = platform.freedesktop_os_release()
    if system.get("ID") != "ubuntu" or system.get("VERSION_ID") not in ("24.04", "26.04") or platform.machine() != "x86_64":
        parser.error("Requer Ubuntu 24.04 ou 26.04 amd64.")
    if not args.prepare_only and not Path("/run/systemd/system").exists():
        parser.error("A instalação normal requer systemd em execução.")
    manifest = json.loads((ROOT / "dist/RELEASE.json").read_text())
    for name, digest in manifest["artifacts"].items():
        if "/" in name or "\\" in name or hashlib.sha256((ROOT / "dist" / name).read_bytes()).hexdigest() != digest:
            raise ValueError("Artefato ausente ou inválido: " + name)
    previous = json.loads(MARKER.read_text()) if MARKER.exists() else None
    if previous:
        if previous.get("product") != "o3-cloud-central" or previous.get("url") != url:
            raise ValueError("Instalação ou URL diferente. Migração exige procedimento explícito; nada foi alterado.")
        if previous.get("ready") and "O3CLOUDCENTRAL_DATABASE_URL=" not in Path("/etc/o3cloudcentral.env").read_text():
            raise ValueError("Esta instalação utiliza nomes anteriores. Execute deploy/migrate-central.py ou faça uma instalação limpa em outra VM.")
        if previous.get("ready") and not args.upgrade:
            print("Central já instalada. Para atualizar preservando os dados, use --upgrade.")
            return
    else:
        if BASE.exists() or DATA.exists() or Path("/etc/o3cloudcentral.env").exists():
            raise ValueError("Instalação existente sem identificação deste instalador; nada foi alterado.")
        try:
            pwd.getpwnam("o3cloudcentral")
        except KeyError:
            pass
        else:
            raise ValueError("Usuário o3cloudcentral já existe; não será reutilizado automaticamente.")
    environment = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update"], env=environment)
    run(["apt-get", "install", "-y", "python3", "python3-venv", "mariadb-server", "ca-certificates", "curl"], env=environment)
    run(["service", "mariadb", "start"] if args.prepare_only else ["systemctl", "enable", "--now", "mariadb"])
    if previous is None:
        exists = sql("SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='o3cloudcentral';")
        account = sql("SELECT User FROM mysql.user WHERE User='o3cloudcentral';")
        if exists or account:
            raise ValueError("Banco ou usuário SQL o3cloudcentral existente. Instalação cancelada para preservar os dados.")
        previous = {"product": "o3-cloud-central", "url": url, "ready": False, "database_ready": False}
        write(MARKER, json.dumps(previous))
    try:
        pwd.getpwnam("o3cloudcentral")
    except KeyError:
        run(["useradd", "--system", "--home-dir", str(DATA), "--shell", "/usr/sbin/nologin", "o3cloudcentral"])
    account = pwd.getpwnam("o3cloudcentral")
    DATA.mkdir(mode=0o700, exist_ok=True)
    os.chown(DATA, account.pw_uid, account.pw_gid)
    os.chmod(DATA, 0o700)
    if not previous.get("database_ready"):
        # Only a marked partial installation reaches this branch. No DROP or reset.
        sql("CREATE DATABASE IF NOT EXISTS o3cloudcentral CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;"
            "CREATE USER IF NOT EXISTS 'o3cloudcentral'@'localhost' IDENTIFIED VIA unix_socket;"
            "GRANT ALL PRIVILEGES ON o3cloudcentral.* TO 'o3cloudcentral'@'localhost';")
        previous["database_ready"] = True
        write(MARKER, json.dumps(previous))
    release_id = manifest["version"] + "-" + str(time.time_ns())
    release = BASE / "releases" / release_id
    release.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT, release, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", ".venv"))
    for item in release.rglob("*"):
        if item.is_symlink():
            raise ValueError("Links simbólicos não são permitidos na distribuição.")
        os.chmod(item, 0o755 if item.is_dir() else 0o644)
    venv = BASE / "venvs" / release_id
    run(["python3", "-m", "venv", str(venv)])
    python = str(venv / "bin/python")
    pip_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
               "PIP_CONFIG_FILE": "/dev/null", "PIP_INDEX_URL": "https://pypi.org/simple",
               "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    run([python, "-m", "pip", "install", "--upgrade", "pip==26.2"], env=pip_env)
    run([python, "-m", "pip", "install", "--require-hashes", "--only-binary=:all:", "--no-deps",
         "-r", str(release / "requirements-central.lock")], env=pip_env)
    run([python, "-m", "pip", "check"], env=pip_env)
    child_env = dict(pip_env, PYTHONPATH=str(release / "python"), O3CLOUDCENTRAL_DATABASE_URL=DSN)
    if not previous.get("ready"):
        # Do not overwrite PKI left by an interrupted initialization.
        if (DATA / "ca.key").exists():
            raise ValueError("Inicialização interrompida deixou PKI. Dados preservados; consulte deploy/INSTALL.md antes de continuar.")
        run(["runuser", "-u", "o3cloudcentral", "--", python, "-B", "-m", "o3cloudcentral", "init-central",
             "--dir", str(DATA), "--url", url, "--names", host + ",localhost,127.0.0.1"], env=child_env)
        previous["ready"] = True
        write(MARKER, json.dumps(previous))
    for name in manifest["artifacts"]:
        target = DATA / name
        temporary = DATA / (name + ".new")
        shutil.copyfile(release / "dist" / name, temporary)
        os.chown(temporary, account.pw_uid, account.pw_gid)
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    old_release = os.readlink(BASE / "current") if (BASE / "current").is_symlink() else None
    old_venv = os.readlink(BASE / "venv") if (BASE / "venv").is_symlink() else None
    env_path = Path("/etc/o3cloudcentral.env")
    unit_path = Path("/etc/systemd/system/o3cloudcentral.service")
    old_env = env_path.read_text() if env_path.exists() else None
    old_unit = unit_path.read_text() if unit_path.exists() else None
    link(BASE / "current", release)
    link(BASE / "venv", venv)
    write(env_path, "PYTHONPATH=/opt/o3cloudcentral/current/python\nO3CLOUDCENTRAL_RESOURCE_ROOT=/opt/o3cloudcentral/current\nO3CLOUDCENTRAL_DATABASE_URL=" + DSN + "\n", 0o640)
    os.chown(env_path, 0, account.pw_gid)
    unit = (release / "deploy/o3cloudcentral.service").read_text().replace("--listen :8443", "--listen :" + str(port))
    write(unit_path, unit, 0o644)
    ca_dir = Path("/etc/o3cloudcentral")
    ca_dir.mkdir(mode=0o755, exist_ok=True)
    shutil.copyfile(DATA / "ca.crt", ca_dir / "ca.crt")
    os.chmod(ca_dir / "ca.crt", 0o644)
    if not args.prepare_only:
        try:
            run(["systemctl", "daemon-reload"])
            run(["systemctl", "enable", "o3cloudcentral"])
            run(["systemctl", "restart", "o3cloudcentral"])
            for attempt in range(30):
                result = subprocess.run(["curl", "--silent", "--fail", "--cacert", str(ca_dir / "ca.crt"),
                    "--connect-to", host + ":" + str(port) + ":127.0.0.1:" + str(port), url + "/login"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise ValueError("A central não respondeu ao teste HTTPS.")
        except Exception:
            if old_release and old_venv:
                link(BASE / "current", old_release)
                link(BASE / "venv", old_venv)
                if old_env is not None: write(env_path, old_env, 0o640); os.chown(env_path, 0, account.pw_gid)
                if old_unit is not None: write(unit_path, old_unit, 0o644)
                run(["systemctl", "daemon-reload"])
                run(["systemctl", "restart", "o3cloudcentral"])
            raise
    previous.update(version=manifest["version"], release=str(release))
    write(MARKER, json.dumps(previous))
    print("\nCentral preparada." if args.prepare_only else "\nCentral instalada e verificada por HTTPS.")
    print("Painel: " + url + "\nPrimeiro acesso: usuário admin / senha admin. A troca de senha é obrigatória.")
    print("Certificado público para confiar no navegador: /etc/o3cloudcentral/ca.crt")
    print("Estado: sudo systemctl status o3cloudcentral\nLogs: sudo journalctl -u o3cloudcentral -n 100")
    print("Regras de rede não foram alteradas. Consulte o README antes de cadastrar os clientes.")

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print("Instalação não concluída: " + str(error), file=sys.stderr)
        sys.exit(1)
