"""Session boundaries, account creation and independent password changes."""
import copy
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from o3cloudcentral.central import create_app, digest, now, stamp
from o3cloudcentral.central_auth import COOKIE
from o3cloudcentral.crypto import hash_admin_password
from test_central import MemoryRepository

HEADERS = {'X-O3CloudCentral-Request':'1'}
ADMIN_PASSWORD = 'fixture-admin-password-123'
USER_PASSWORD = 'fixture-technician-password-123'


@pytest.fixture
def accounts(tmp_path):
    repository = MemoryRepository()
    repository.state['admin_hash'] = hash_admin_password(ADMIN_PASSWORD)
    (tmp_path/'ca.crt').write_text('public-fixture')
    app = create_app(repository,tmp_path,monitor=False)
    with TestClient(app,base_url='https://central.example') as client:
        yield client,repository,app


def login(client, username='admin', password=ADMIN_PASSWORD):
    return client.post('/api/auth/login',json={'username':username,'password':password},headers=HEADERS)


def test_login_redirect_secure_cookie_logout_invalidates_replay(accounts):
    client,repository,_=accounts
    root=client.get('/',follow_redirects=False)
    assert root.status_code == 303 and root.headers['location']=='/login'
    assert client.get('/login').status_code==200
    assert client.get('/login.js').status_code==200
    anonymous=client.get('/api/admin/state')
    assert anonymous.status_code==401 and 'WWW-Authenticate' not in anonymous.headers
    response=login(client)
    assert response.status_code==200
    cookie=response.headers['set-cookie']
    assert COOKIE in cookie and 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=strict' in cookie and 'Path=/' in cookie
    raw=client.cookies.get(COOKIE)
    assert raw not in json.dumps(repository.read()) and digest(raw) in repository.read()['sessions']
    assert client.get('/api/auth/me').json()=={'username':'admin'}
    assert client.get('/api/admin/state').json()['username']=='admin'
    assert client.get('/').status_code==200
    assert client.get('/login',follow_redirects=False).headers['location']=='/'
    logout=client.post('/api/auth/logout',json={},headers=HEADERS)
    assert logout.status_code==200
    assert client.get('/api/admin/state').status_code==401
    assert client.get('/api/admin/state',headers={'Cookie':COOKIE+'='+raw}).status_code==401


def test_cookie_csrf_and_login_csrf_are_enforced(accounts):
    client,_,_=accounts
    assert client.post('/api/auth/login',json={'username':'admin','password':ADMIN_PASSWORD}).status_code==403
    assert client.post('/api/auth/login',json={'username':'admin','password':ADMIN_PASSWORD},headers={**HEADERS,'Origin':'https://evil.example'}).status_code==403
    assert login(client).status_code==200
    for path,body in (('/api/admin/users',{'username':'technician','password':USER_PASSWORD}),('/api/auth/logout',{})):
        assert client.post(path,json=body).status_code==403
        assert client.post(path,json=body,headers={**HEADERS,'Origin':'https://evil.example'}).status_code==403
    assert client.get('/api/auth/me').status_code==200


def test_user_creation_login_and_own_password_rotation(accounts):
    client,repository,app=accounts
    assert client.post('/api/admin/users',json={'username':'technician','password':USER_PASSWORD},headers=HEADERS).status_code==401
    assert login(client).status_code==200
    result=client.post('/api/admin/users',json={'username':'Tecnico.Silva','password':USER_PASSWORD},headers=HEADERS)
    assert result.status_code==200 and result.json()['username']=='tecnico.silva'
    stored=repository.read()['users']['tecnico.silva']['password_hash']
    assert stored.startswith('scrypt$') and USER_PASSWORD not in json.dumps(repository.read())
    assert client.post('/api/admin/users',json={'username':'TECNICO.SILVA','password':USER_PASSWORD},headers=HEADERS).status_code==409
    for invalid in ('admin','bad space','ab','équipe'):
        assert client.post('/api/admin/users',json={'username':invalid,'password':USER_PASSWORD},headers=HEADERS).status_code in (400,409)
    assert client.post('/api/admin/users',json={'username':'valid-user','password':'short'},headers=HEADERS).status_code==400
    listed=client.get('/api/admin/users')
    assert {u['username'] for u in listed.json()['users']}=={'admin','tecnico.silva'}
    assert stored not in listed.text and stored not in client.get('/api/admin/state').text
    with TestClient(app,base_url='https://central.example') as technician:
        assert login(technician,'tecnico.silva',USER_PASSWORD).status_code==200
        assert technician.get('/api/admin/state').json()['username']=='tecnico.silva'
        # The current model grants the same panel access to every account.
        assert technician.post('/api/admin/users',json={'username':'second-user','password':USER_PASSWORD},headers=HEADERS).status_code==200
        raw=technician.cookies.get(COOKIE)
        wrong=technician.post('/api/admin/account/password',json={'current_password':'wrong','new_password':'new-fixture-password-123'},headers=HEADERS)
        assert wrong.status_code==400
        changed=technician.post('/api/admin/account/password',json={'current_password':USER_PASSWORD,'new_password':'new-fixture-password-123'},headers=HEADERS)
        assert changed.status_code==200
        assert technician.get('/api/admin/state',headers={'Cookie':COOKIE+'='+raw}).status_code==401
        technician.cookies.clear()
        assert login(technician,'tecnico.silva',USER_PASSWORD).status_code==401
        assert login(technician,'tecnico.silva','new-fixture-password-123').status_code==200
    # Changing a technician password does not change admin or its session.
    assert client.get('/api/admin/state').status_code==200
    assert repository.read()['admin_hash']!=repository.read()['users']['tecnico.silva']['password_hash']


def test_session_expiry_and_admin_rotation_revoke_all_its_sessions(accounts):
    client,repository,app=accounts
    assert login(client).status_code==200
    raw=client.cookies.get(COOKIE)
    repository.transaction(lambda state:state['sessions'][digest(raw)].update(expires=stamp(now()-timedelta(seconds=1))))
    assert client.get('/api/auth/me').status_code==401
    assert login(client).status_code==200
    assert digest(raw) not in repository.read()['sessions']
    with TestClient(app,base_url='https://central.example') as second:
        assert login(second).status_code==200
        changed=client.post('/api/admin/account/password',json={'current_password':ADMIN_PASSWORD,'new_password':'admin-new-fixture-password-123'},headers=HEADERS)
        assert changed.status_code==200
        assert second.get('/api/auth/me').status_code==401
    assert client.get('/api/auth/me').status_code==401
    client.cookies.clear()
    assert login(client,password='admin-new-fixture-password-123').status_code==200


def test_bad_login_generic_error_rate_limit_and_no_state_changes(accounts,monkeypatch):
    client,repository,app=accounts
    from o3cloudcentral import central
    monkeypatch.setattr(central,'check_admin_password',lambda *_:False)
    before=copy.deepcopy(repository.read())
    existing=login(client,password='bad')
    missing=login(client,'unknown','bad')
    assert existing.status_code==missing.status_code==401 and existing.text==missing.text
    assert 'WWW-Authenticate' not in existing.headers
    results=[login(client,password='bad').status_code for _ in range(22)]
    assert 429 in results and repository.read()==before
