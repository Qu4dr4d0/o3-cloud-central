"""Compatibility with the deployed Go 0.4 terminal's actual SSH protocol."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil

import pytest

from test_gateway_runtime import Lab
from edgehub.gateway_policy import snapshot_revision


GO_CLIENT = r'''
package main
import("crypto/sha256";"encoding/hex";"encoding/json";"fmt";"io";"net";"os";"time";"golang.org/x/crypto/ssh")
type Service struct { ID string `json:"id"`; Name string `json:"name"`; Target string `json:"target"`; Port int `json:"port"`; LocalPort int `json:"local_port"`; Protocol string `json:"protocol,omitempty"`; Type string `json:"type,omitempty"` }
type Device struct { ID string `json:"id"`; PublicKey string `json:"public_key"`; Services []Service `json:"services"` }
type Snapshot struct { Autonomous bool `json:"autonomous,omitempty"`; Revision string `json:"revision,omitempty"`; Endpoint string `json:"endpoint,omitempty"`; Devices []Device `json:"devices"`; Services []Service `json:"services"`; Lease int `json:"lease_seconds"` }
func main(){
 if os.Args[1]=="revision" { var s Snapshot; if e:=json.NewDecoder(os.Stdin).Decode(&s);e!=nil{panic(e)};s.Revision=""; b,_:=json.Marshal(s);h:=sha256.Sum256(b);fmt.Print(hex.EncodeToString(h[:]));return }
 keyraw,e:=os.ReadFile(os.Args[2]);if e!=nil{panic(e)};key,e:=ssh.ParsePrivateKey(keyraw);if e!=nil{panic(e)}
 expected,e:=os.ReadFile(os.Args[3]);if e!=nil{panic(e)};host,_,_,_,e:=ssh.ParseAuthorizedKey(expected);if e!=nil{panic(e)}
 c,e:=ssh.Dial("tcp",os.Args[1],&ssh.ClientConfig{User:"terminal-one",Auth:[]ssh.AuthMethod{ssh.PublicKeys(key)},HostKeyCallback:ssh.FixedHostKey(host),Timeout:5*time.Second});if e!=nil{panic(e)};defer c.Close()
 ok,raw,e:=c.SendRequest("policy-v1@edgehub",true,nil);if e!=nil||!ok{panic("policy")};var p struct{Control int `json:"control_version"`;Services []Service `json:"services"`};if json.Unmarshal(raw,&p)!=nil||p.Control!=1||len(p.Services)!=1{panic("policy json")}
 info:=[]byte(`{"hostname":"LEGACY-GO","local_ip":"192.168.10.25","agent_version":"0.4.0-lab","os":"windows"}`);ok,_,e=c.SendRequest("identity-v1@edgehub",true,info);if e!=nil||!ok{panic("identity")}
 conn,e:=c.Dial("tcp",net.JoinHostPort(p.Services[0].Target,fmt.Sprint(p.Services[0].Port)));if e!=nil{panic(e)};defer conn.Close();conn.SetDeadline(time.Now().Add(5*time.Second));conn.Write([]byte("compat"));b:=make([]byte,6);if _,e=io.ReadFull(conn,b);e!=nil||string(b)!="compat"{panic("relay")}
 ok,_,e=c.SendRequest("identity-v1@edgehub",true,[]byte(`{"id":"other","hostname":"spoof"}`));if e!=nil||ok{panic("spoof accepted")}
 if session,e:=c.NewSession();e==nil{session.Close();panic("session allowed")};fmt.Print("legacy-go-ok")
}
'''


@pytest.fixture(scope="module")
def legacy_client(tmp_path_factory):
    go = os.environ.get("EDGEHUB_GO") or shutil.which("go")
    root = Path(__file__).resolve().parents[2]
    if not go:
        candidate = root.parent / ".edgehub-tools/go/bin/go.exe"
        go = str(candidate) if candidate.exists() else None
    if not go or not (root / "go.mod").exists():
        pytest.skip("Optional legacy comparison requires the original Go reference tree")
    directory = tmp_path_factory.mktemp("go-client")
    source = directory / "legacy_client.go"
    binary = directory / ("legacy_client.exe" if os.name == "nt" else "legacy_client")
    source.write_text(GO_CLIENT)
    import subprocess
    result = subprocess.run([go, "build", "-o", str(binary), str(source)], cwd=root, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stderr.decode()
    return binary


@pytest.mark.asyncio
async def test_legacy_go_client_policy_identity_and_forwarding(tmp_path, legacy_client):
    lab = await Lab().start(tmp_path)
    try:
        key, host = tmp_path / "terminal.key", tmp_path / "gateway.pub"
        key.write_bytes(lab.device_key.export_private_key())
        host.write_text(lab.gateway.host_key)
        process = await asyncio.create_subprocess_exec(str(legacy_client), f"127.0.0.1:{lab.gateway_port}", str(key), str(host), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(process.communicate(), 15)
        assert process.returncode == 0, err.decode()
        assert out == b"legacy-go-ok"
    finally:
        await lab.close()


def test_revision_is_byte_compatible_with_go_struct_json(legacy_client):
    import subprocess
    snapshots = [
        {"autonomous": True, "devices": [], "services": [], "lease_seconds": 300},
        {"autonomous": True, "devices": None, "services": None, "lease_seconds": 0},
        {"autonomous": True, "endpoint": "example.com:2222", "devices": [{"id": "d1", "public_key": "key\n", "services": [{"id": "s1", "name": "Gestão <&>\u2028", "target": "192.168.1.2", "port": 80, "local_port": 18080, "protocol": "TCP", "type": "HTTP"}]}], "services": [], "lease_seconds": 300},
    ]
    for snapshot in snapshots:
        result = subprocess.run([str(legacy_client), "revision"], input=json.dumps(snapshot).encode(), capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr.decode()
        assert result.stdout.decode() == snapshot_revision(snapshot)
