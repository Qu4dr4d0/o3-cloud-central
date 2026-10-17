#!/usr/bin/env python3
"""Migrate a managed local central, preserving SQL data, PKI and passwords.

The previous database/prefix/user are discovered from the installed service.
The original database remains intact until the new service passes HTTPS checks.
No credential or private key is exported or logged.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
TARGET = "o3cloudcentral"
PREFIX = TARGET + "_"
SUFFIXES = ("schema", "settings", "sites", "services", "devices",
            "device_services", "gateway_reports", "tickets", "auth_users", "auth_sessions")
ENV = Path("/etc/o3cloudcentral.env")
UNIT = Path("/etc/systemd/system/o3cloudcentral.service")
MARKER = Path("/etc/o3cloudcentral-install.json")
JOURNAL = Path("/etc/o3cloudcentral-migration.json")

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sql(statement):
    return subprocess.check_output(
        ["mariadb", "--batch", "--raw", "--skip-column-names", "-e", statement], text=True).strip()

def identifier(value):
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,63}", value):
        raise ValueError("Identificador de origem inválido.")
    return "`" + value + "`"

def write(path, content, mode=0o600):
    temporary = path.with_name(path.name + ".new")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(mode)
    os.replace(temporary, path)

def configuration():
    values = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    dsns = [value for key, value in values.items() if key.endswith("_DATABASE_URL")]
    if len(dsns) != 1:
        raise ValueError("Não foi possível identificar o banco da central instalada.")
    parsed = urlsplit(dsns[0])
    source, user = unquote(parsed.path.lstrip("/")), unquote(parsed.username or "")
    identifier(source); identifier(user)
    if parsed.scheme != "mysql+pymysql" or parsed.hostname not in ("localhost", "127.0.0.1") or parsed.password:
        raise ValueError("A migração automática requer MariaDB local via socket Unix.")
    unit = UNIT.read_text()
    if not re.search(r"^User=" + re.escape(user) + r"$", unit, re.M):
        raise ValueError("Usuário SQL e usuário do serviço não correspondem.")
    found = re.search(r"^WorkingDirectory=(/var/lib/[a-zA-Z0-9_-]+)$", unit, re.M)
    if not found:
        raise ValueError("Diretório de dados desconhecido.")
    data = Path(found[1])
    if data.is_symlink() or not data.is_dir() or not (data / "ca.key").is_file():
        raise ValueError("Diretório de identidade inválido; nenhuma alteração foi feita.")
    tables = sql("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + source + "' AND TABLE_TYPE='BASE TABLE';").splitlines()
    prefixes = [name[:-len("settings")] for name in tables if name.endswith("_settings")]
    if len(prefixes) != 1:
        raise ValueError("Não foi possível identificar o esquema da aplicação.")
    prefix = prefixes[0]
    identifier(prefix + "settings")
    if set(tables) != {prefix + suffix for suffix in SUFFIXES}:
        raise ValueError("O banco possui tabelas inesperadas; migração automática recusada.")
    if sql("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + source + "';") != "10":
        raise ValueError("O banco possui views ou objetos adicionais.")
    if sql("SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA='" + source + "';") != "0":
        raise ValueError("O banco possui triggers; exige migração assistida.")
    if sql("SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA='" + source + "';") != "0":
        raise ValueError("O banco possui rotinas; exige migração assistida.")
    if sql("SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA='" + source + "';") != "0":
        raise ValueError("O banco possui eventos; exige migração assistida.")
    return source, user, data, prefix

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="Somente para um ambiente de teste sem systemd")
    parser.add_argument("--adopt-existing", action="store_true", help="Permite migrar uma central anterior ao instalador oficial")
    parser.add_argument("--plan", action="store_true", help="Confere a origem sem alterar dados")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Execute com sudo.")
    if JOURNAL.exists():
        raise ValueError("Há uma migração interrompida. Preserve os bancos e consulte o arquivo de recuperação antes de prosseguir.")
    if not MARKER.exists() and not args.adopt_existing:
        raise ValueError("Central não identificada pelo instalador. Revise a origem e use --adopt-existing explicitamente.")
    source, user, data, prefix = configuration()
    if source == TARGET and prefix == PREFIX and user == TARGET and data == Path("/var/lib") / TARGET:
        print("A instalação já utiliza a nomenclatura atual.")
        return
    if source == TARGET or user == TARGET or data == Path("/var/lib") / TARGET:
        raise ValueError("Migração parcial detectada; exige recuperação assistida.")
    account = pwd.getpwnam(user)
    if account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
        raise ValueError("O usuário da origem não é uma conta exclusiva de serviço.")
    try:
        pwd.getpwnam(TARGET)
    except KeyError:
        pass
    else:
        raise ValueError("O usuário de destino já existe.")
    if (Path("/var/lib") / TARGET).exists():
        raise ValueError("O diretório de destino já existe.")
    if sql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='" + TARGET + "';"):
        raise ValueError("O banco de destino já existe; nenhuma tabela será sobrescrita.")
    if sql("SELECT User FROM mysql.user WHERE User='" + TARGET + "';"):
        raise ValueError("O usuário SQL de destino já existe.")
    grants = sql("SHOW GRANTS FOR '" + user + "'@'localhost';").splitlines()
    if any("GRANT USAGE ON *.*" not in grant and ("ON `" + source + "`.*") not in grant for grant in grants):
        raise ValueError("O usuário SQL possui permissões fora da aplicação.")
    url = sql("SELECT url FROM " + identifier(source) + "." + identifier(prefix + "settings") + " WHERE id=1;")
    if not url.startswith("https://"):
        raise ValueError("URL da central inválida.")
    if args.plan:
        print("Origem validada: 10 tabelas, usuário de serviço, MariaDB local e PKI existentes. Destino: o3cloudcentral.")
        return
    old_env, old_unit = ENV.read_text(), UNIT.read_text()
    old_marker = MARKER.read_text() if MARKER.exists() else None
    new_data = Path("/var/lib") / TARGET
    renamed_user = renamed_group = moved_data = created_database = created_user = False
    successful = False
    journal = {"source_database":source, "source_user":user, "source_data":str(data),
               "source_prefix":prefix, "target_database":TARGET, "phase":"starting"}
    write(JOURNAL, json.dumps(journal, indent=2))
    try:
        if not args.prepare_only:
            run(["systemctl", "stop", "o3cloudcentral"])
        source_count = {suffix:int(sql("SELECT COUNT(*) FROM " + identifier(source) + "." + identifier(prefix+suffix))) for suffix in SUFFIXES}
        # The source is never modified during copying.
        sql("CREATE DATABASE " + identifier(TARGET) + " CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;")
        created_database = True
        for suffix in SUFFIXES:
            ddl = sql("SHOW CREATE TABLE " + identifier(source) + "." + identifier(prefix+suffix)).split("\t",1)[1]
            ddl = ddl.replace(prefix, PREFIX)
            sql("USE " + identifier(TARGET) + "; SET FOREIGN_KEY_CHECKS=0; " + ddl + ";")
        statements = ["START TRANSACTION"]
        for suffix in SUFFIXES:
            statements.append("INSERT INTO " + identifier(TARGET) + "." + identifier(PREFIX+suffix) +
                              " SELECT * FROM " + identifier(source) + "." + identifier(prefix+suffix))
        statements.append("COMMIT")
        sql(";".join(statements)+";")
        for suffix in SUFFIXES:
            old = identifier(source) + "." + identifier(prefix+suffix)
            new = identifier(TARGET) + "." + identifier(PREFIX+suffix)
            columns = sql("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='" + source +
                          "' AND TABLE_NAME='" + prefix+suffix + "' ORDER BY ORDINAL_POSITION").splitlines()
            comparisons = " AND ".join("n."+identifier(col)+" <=> o."+identifier(col) for col in columns)
            matched = int(sql("SELECT COUNT(*) FROM " + new + " n JOIN " + old + " o ON " + comparisons))
            if matched != source_count[suffix] or int(sql("SELECT COUNT(*) FROM " + new)) != source_count[suffix]:
                raise ValueError("Conferência de dados falhou; origem preservada.")
        old_key, new_key = "_" + prefix + "position", "_" + PREFIX + "position"
        sql("UPDATE " + identifier(TARGET) + "." + identifier(PREFIX+"services") +
            " SET data=JSON_REMOVE(JSON_SET(data, '$." + new_key + "', JSON_EXTRACT(data, '$." +
            old_key + "')), '$." + old_key + "') WHERE JSON_CONTAINS_PATH(data,'one','$." + old_key + "');")
        sql("CREATE USER 'o3cloudcentral'@'localhost' IDENTIFIED VIA unix_socket;"
            "GRANT ALL PRIVILEGES ON o3cloudcentral.* TO 'o3cloudcentral'@'localhost';")
        created_user = True
        run(["usermod", "--login", TARGET, "--home", str(new_data), user])
        renamed_user = True
        run(["groupmod", "--new-name", TARGET, user])
        renamed_group = True
        os.rename(data, new_data)
        moved_data = True
        # Keep the previous active code available for rollback until validation.
        write(ENV, "PYTHONPATH=/opt/o3cloudcentral/current/python\nO3CLOUDCENTRAL_RESOURCE_ROOT=/opt/o3cloudcentral/current\n"
              "O3CLOUDCENTRAL_DATABASE_URL=mysql+pymysql://o3cloudcentral@localhost/o3cloudcentral?unix_socket=/run/mysqld/mysqld.sock\n",0o640)
        os.chown(ENV,0,account.pw_gid)
        write(MARKER,json.dumps({"product":"o3-cloud-central","url":url,"ready":True,"database_ready":True}))
        journal["phase"]="copied"; write(JOURNAL,json.dumps(journal,indent=2))
        command = [sys.executable,str(ROOT/"deploy/install-central.py"),"--url",url,"--upgrade"]
        if args.prepare_only: command.append("--prepare-only")
        run(command)
        # Child installer verifies HTTPS in the normal systemd mode.
        successful = True
        journal["phase"]="verified"; write(JOURNAL,json.dumps(journal,indent=2))
    finally:
        if not successful:
            if not args.prepare_only:
                subprocess.run(["systemctl","stop","o3cloudcentral"],check=False)
            if moved_data: os.rename(new_data,data)
            if renamed_group:
                run(["groupmod","--new-name",user,TARGET])
            if renamed_user:
                run(["usermod","--login",user,"--home",str(data),TARGET])
            write(ENV,old_env,0o640); os.chown(ENV,0,account.pw_gid)
            write(UNIT,old_unit,0o644)
            if old_marker is None: MARKER.unlink(missing_ok=True)
            else: write(MARKER,old_marker)
            # Remove only the destination created by this attempt.
            if created_database: sql("DROP DATABASE " + identifier(TARGET))
            if created_user: sql("DROP USER 'o3cloudcentral'@'localhost'")
            if not args.prepare_only:
                run(["systemctl","daemon-reload"]); run(["systemctl","restart","o3cloudcentral"])
            JOURNAL.unlink(missing_ok=True)
    # Only after verified activation: remove the old database/account.
    sql("DROP DATABASE " + identifier(source) + "; DROP USER '" + user + "'@'localhost';")
    JOURNAL.unlink()
    print("Migração concluída: banco, tabelas, conta de serviço e dados usam o3cloudcentral. Cadastros, senhas e CA preservados.")

if __name__=="__main__":
    try: main()
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        print("Migração não concluída: "+str(error),file=sys.stderr)
        sys.exit(1)
