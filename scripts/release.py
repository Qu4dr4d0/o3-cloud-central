"""Create a public release with generic payloads only, never enrollment state."""
from pathlib import Path
import hashlib
import json
import tarfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.7.3"
ARTIFACTS = ("O3CloudCentral.exe", "pfSense-pkg-O3CloudCentral-0.7.2.pkg", "O3CloudCentral-linux-amd64.tar.gz")

def main():
    dist = ROOT / "dist"
    windows = dist / "python/O3CloudCentral.exe"
    if windows.exists():
        (dist / "O3CloudCentral.exe").write_bytes(windows.read_bytes())
    artifacts = {name:hashlib.sha256((dist/name).read_bytes()).hexdigest() for name in ARTIFACTS}
    (dist/"RELEASE.json").write_text(json.dumps({"version":VERSION,"artifacts":artifacts},indent=2)+"\n")
    allowed = {".gitignore",".gitattributes","README.md","pyproject.toml","requirements-python.txt",
               "requirements-central.lock","THIRD_PARTY_NOTICES.txt","install.sh"}
    roots = ("python/o3cloudcentral","python/tests","web","assets","deploy","scripts")
    paths = [ROOT/name for name in sorted(allowed)]
    for folder in roots:
        paths.extend(sorted(path for path in (ROOT/folder).rglob("*") if path.is_file()
                     and "__pycache__" not in path.parts and path.suffix != ".pyc"))
    paths.extend(dist/name for name in (*ARTIFACTS,"RELEASE.json"))
    output = dist / ("o3-cloud-central-"+VERSION+".tar.gz")
    with tarfile.open(output,"w:gz",format=tarfile.PAX_FORMAT) as bundle:
        for path in paths:
            if path.is_symlink(): raise ValueError("Symbolic link in release: "+str(path))
            relative = path.relative_to(ROOT).as_posix()
            info = bundle.gettarinfo(str(path),"o3-cloud-central-"+VERSION+"/"+relative)
            info.uid=info.gid=0;info.uname=info.gname="";info.mode=0o644
            with path.open("rb") as source: bundle.addfile(info,source)
    sums = {output.name:hashlib.sha256(output.read_bytes()).hexdigest(),**artifacts,
            "install.sh":hashlib.sha256((ROOT/"install.sh").read_bytes()).hexdigest()}
    (dist/"SHA256SUMS").write_text("".join(digest+"  "+name+"\n" for name,digest in sums.items()))
    print(json.dumps({"release":str(output),"bytes":output.stat().st_size,"sha256":sums[output.name]}))

if __name__=="__main__": main()
