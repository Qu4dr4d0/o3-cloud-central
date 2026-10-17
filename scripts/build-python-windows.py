"""Build the Python Windows installer, without installing or elevating it."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, default=ROOT.parent / ".o3cloudcentral-python" / "Scripts" / "python.exe")
    arguments = parser.parse_args()
    if os.name != "nt":
        parser.error("Execute o empacotamento Windows em um host Windows.")
    output = ROOT / "dist" / "python"
    work = ROOT.parent / ".o3-cloud-central-python-build"
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    version_file = work / "windows-version.txt"
    version_file.write_text("""VSVersionInfo(
  ffi=FixedFileInfo(filevers=(0,7,0,0), prodvers=(0,7,0,0), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0,0)),
  kids=[StringFileInfo([StringTable('041604B0', [
    StringStruct('CompanyName','O3 Cloud'), StringStruct('FileDescription','O3 Cloud Central'),
    StringStruct('FileVersion','0.7.0.0'), StringStruct('InternalName','O3CloudCentral'),
    StringStruct('OriginalFilename','O3CloudCentral.exe'), StringStruct('ProductName','O3 Cloud Central'),
    StringStruct('ProductVersion','0.7.0')])]),
    VarFileInfo([VarStruct('Translation',[1046,1200])])])
""", encoding="utf-8")
    manifest = work / "O3CloudCentral.manifest"
    manifest.write_text((ROOT / "assets" / "O3CloudCentral.manifest").read_text(encoding="utf-8"), encoding="utf-8")
    hidden = ("servicemanager", "win32serviceutil", "win32service", "win32security", "win32pipe", "win32file",
        "win32event", "win32api", "win32process", "win32ts", "pywintypes", "pythoncom", "win32com.client",
        "win32com.shell.shell", "win32com.shell.shellcon", "pystray._win32", "PIL.Image", "PIL.ImageDraw", "PIL.ImageFont",
        "tkinter", "tkinter.scrolledtext", "pymysql", "sqlalchemy.dialects.mysql.pymysql", "sqlalchemy.dialects.mysql.mariadb",
        "uvicorn.logging", "uvicorn.loops.auto", "uvicorn.protocols.http.auto", "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets.auto", "uvicorn.lifespan.on")
    command = [str(arguments.python), "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--name", "O3CloudCentral", "--paths", str(ROOT / "python"), "--distpath", str(output), "--workpath", str(work / "build"),
        "--specpath", str(work), "--icon", str(ROOT / "assets" / "O3CloudCentral.ico"),
        "--version-file", str(version_file), "--manifest", str(manifest),
        "--add-data", str(ROOT / "web") + os.pathsep + "web", "--add-data", str(ROOT / "assets") + os.pathsep + "assets"]
    for module in hidden:
        command.extend(["--hidden-import", module])
    command.append(str(ROOT / "python" / "o3cloudcentral" / "__main__.py"))
    subprocess.run(command, cwd=ROOT, check=True)
    executable = output / "O3CloudCentral.exe"
    if not executable.is_file() or not 0 < executable.stat().st_size <= 128 << 20:
        raise RuntimeError("Executável fora do limite de distribuição.")
    summary = {"name": "O3 Cloud Central", "file": executable.name, "version": "0.7.0", "language": "Python", "bytes": executable.stat().st_size,
        "sha256": hashlib.file_digest(executable.open("rb"), "sha256").hexdigest()}
    (output / "windows-build.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
