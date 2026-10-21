"""Installer identity isolation, including a matching human login name."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pwd")
pytest.importorskip("grp")
source = Path(__file__).resolve().parents[2] / "deploy/install-central.py"
spec = importlib.util.spec_from_file_location("central_installer", source)
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

def missing(name):
    raise KeyError(name)

def account(name, *, uid=990, shell="/usr/sbin/nologin"):
    return SimpleNamespace(pw_name=name,pw_uid=uid,pw_gid=990,pw_shell=shell,pw_dir=str(installer.DATA))

def test_matching_human_login_is_not_inspected_or_reused(monkeypatch):
    calls=[]
    def get(name):
        calls.append(name)
        if name=="o3cloudcentral":
            return account(name,uid=1000,shell="/bin/bash")
        raise KeyError(name)
    monkeypatch.setattr(installer.pwd,"getpwnam",get)
    monkeypatch.setattr(installer.grp,"getgrnam",missing)
    assert installer.select_service_user(None)=="_o3cloudcentral"
    assert calls==["_o3cloudcentral"]
    assert "_o3cloudcentral@localhost/o3cloudcentral?" in installer.database_url("_o3cloudcentral")

def test_unmanaged_reserved_account_is_refused(monkeypatch):
    monkeypatch.setattr(installer.pwd,"getpwnam",lambda name:account(name))
    with pytest.raises(ValueError,match="reservada"):
        installer.select_service_user(None)

def test_existing_070_service_keeps_its_account(monkeypatch,tmp_path):
    unit=tmp_path/"service";unit.write_text("User=o3cloudcentral\n")
    monkeypatch.setattr(installer,"UNIT",unit)
    monkeypatch.setattr(installer.pwd,"getpwnam",lambda name:account(name))
    monkeypatch.setattr(installer.grp,"getgrgid",lambda gid:SimpleNamespace(gr_name="o3cloudcentral"))
    assert installer.select_service_user({"ready":True})=="o3cloudcentral"

@pytest.mark.parametrize("uid,shell",[(1000,"/bin/bash"),(1000,"/usr/sbin/nologin"),(0,"/usr/sbin/nologin")])
def test_human_or_root_account_is_never_adopted(monkeypatch,uid,shell):
    monkeypatch.setattr(installer.pwd,"getpwnam",lambda name:account(name,uid=uid,shell=shell))
    monkeypatch.setattr(installer.grp,"getgrgid",lambda gid:SimpleNamespace(gr_name="_o3cloudcentral"))
    with pytest.raises(ValueError,match="exclusiva"):
        installer.select_service_user({"ready":True,"service_user":"_o3cloudcentral"})

def test_account_name_from_marker_is_allowlisted():
    with pytest.raises(ValueError,match="desconhecida"):
        installer.select_service_user({"ready":True,"service_user":"root"})
