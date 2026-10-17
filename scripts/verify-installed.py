"""Exercise a fresh disposable installation, including mandatory password change."""
import json
import ssl
import urllib.error
import urllib.request
import http.cookiejar

context = ssl.create_default_context(cafile="/etc/o3cloudcentral/ca.crt")
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar))
base = "https://localhost:8443"

def request(path, value=None, expected=200, basic=None):
    headers = {"X-EdgeHub-Request":"1"}
    if basic: headers["Authorization"] = basic
    data = json.dumps(value).encode() if value is not None else None
    if data is not None: headers["Content-Type"] = "application/json"
    try:
        response = client.open(urllib.request.Request(base+path,data=data,headers=headers),timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    assert response.code == expected, (path,response.code,response.read())
    return response.read()

assert json.loads(request("/api/auth/login",{"username":"admin","password":"admin"}))["must_change_password"]
request("/api/admin/state",expected=403)
request("/api/admin/users",{"username":"bypass","password":"fixture-passphrase-123"},expected=403)
request("/api/admin/account/password",{"current_password":"admin","new_password":"temporary-test-password-123"})
request("/api/admin/state",expected=401)
request("/api/auth/login",{"username":"admin","password":"admin"},expected=401)
assert not json.loads(request("/api/auth/login",{"username":"admin","password":"temporary-test-password-123"}))["must_change_password"]
request("/api/admin/state")
print("HTTPS, login inicial, bloqueio de gerenciamento, troca obrigatória e novo login: OK")
