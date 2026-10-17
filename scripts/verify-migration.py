"""Populate and verify only a disposable GitHub Actions migration fixture."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit
from sqlalchemy.engine import make_url

if os.environ.get("GITHUB_ACTIONS") != "true":
    raise SystemExit("Execute apenas na VM descartável do GitHub Actions.")
before = sys.argv[1] == "before"
root = Path("/opt/o3cloudcentral/current")
package = next(path.name for path in (root/"python").iterdir() if (path/"storage.py").is_file())
sys.path.insert(0,str(root/"python"))
storage = importlib.import_module(package+".storage")
env = dict(line.split("=",1) for line in Path("/etc/o3cloudcentral.env").read_text().splitlines() if "=" in line)
dsn = next(value for key,value in env.items() if key.endswith("_DATABASE_URL"))
dsn = str(make_url(dsn).set(username="root",password=None))
repo = storage.StateRepository(dsn)
fixture = Path("/tmp/o3-migration-fingerprint.json")
if before:
    def populate(state):
        state["sites"]["fixture-client"] = {"id":"fixture-client","name":"Cliente de teste",
            "endpoint":"gateway.example.com:2222","services":[
                {"id":"fixture-service","name":"Web","target":"172.30.20.10","port":80,"local_port":18080,"protocol":"TCP"}]}
        state["devices"]["fixture-device"] = {"id":"fixture-device","site_id":"fixture-client",
            "name":"Terminal preservado","hostname":"fixture-host","services":["fixture-service"]}
    repo.transaction(populate)
state = repo.read()
repo.close()
state.pop("sessions",None)
fingerprint = hashlib.sha256(json.dumps(state,sort_keys=True).encode()).hexdigest()
data = next(value for value in Path("/etc/systemd/system/o3cloudcentral.service").read_text().splitlines()
            if value.startswith("WorkingDirectory=")).split("=",1)[1]
ca = hashlib.sha256((Path(data)/"ca.crt").read_bytes()).hexdigest()
if before:
    fixture.write_text(json.dumps({"state":fingerprint,"ca":ca,"database":urlsplit(dsn).path.lstrip("/")}))
else:
    previous = json.loads(fixture.read_text())
    assert fingerprint == previous["state"], "State changed during migration"
    assert ca == previous["ca"], "CA changed during migration"
    tables = subprocess.check_output(["mariadb","--batch","--skip-column-names","-e",
        "SHOW TABLES FROM o3cloudcentral"],text=True).splitlines()
    assert len(tables)==10 and all(name.startswith("o3cloudcentral_") for name in tables)
    remaining = subprocess.check_output(["mariadb","--batch","--skip-column-names","-e",
        "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='"+previous["database"]+"'"],text=True).strip()
    assert not remaining
    print("Cadastros, permissões, senha e CA preservados; banco e 10 tabelas migrados: OK")
