"""The bootstrap credential must never authorize management, including Basic."""
import base64
import pytest
from fastapi.testclient import TestClient
from o3cloudcentral.central import create_app
from o3cloudcentral.crypto import hash_admin_password, check_admin_password
from test_central import MemoryRepository

HEADERS = {'X-O3CloudCentral-Request':'1'}

def test_first_access_enforced_in_backend_and_cleared_by_password_change(tmp_path):
    repo = MemoryRepository()
    repo.state['admin_hash'] = 'bootstrap$' + hash_admin_password('admin')
    (tmp_path/'ca.crt').write_text('public-fixture')
    with TestClient(create_app(repo,tmp_path,monitor=False),base_url='https://central.example') as client:
        response = client.post('/api/auth/login',json={'username':'admin','password':'admin'},headers=HEADERS)
        assert response.json()['must_change_password'] is True
        assert client.get('/',follow_redirects=False).headers['location']=='/first-access'
        assert client.get('/first-access').status_code==200
        assert client.get('/api/admin/state').status_code==403
        assert client.get('/api/admin/users').status_code==403
        assert client.post('/api/admin/sites',json={},headers=HEADERS).status_code==403
        assert client.post('/api/admin/users',json={},headers=HEADERS).status_code==403
        assert client.post('/api/admin/account/password',json={'current_password':'admin','new_password':'admin'},headers=HEADERS).status_code==400
        assert client.post('/api/admin/account/password',json={'current_password':'wrong','new_password':'new-secure-passphrase'},headers=HEADERS).status_code==400
        changed = client.post('/api/admin/account/password',json={'current_password':'admin','new_password':'new-secure-passphrase'},headers=HEADERS)
        assert changed.status_code==200
        assert client.get('/api/admin/state').status_code==401
        assert not repo.read()['admin_hash'].startswith('bootstrap$')
        assert check_admin_password(repo.read()['admin_hash'],'new-secure-passphrase')
        assert client.post('/api/auth/login',json={'username':'admin','password':'admin'},headers=HEADERS).status_code==401
        assert client.post('/api/auth/login',json={'username':'admin','password':'new-secure-passphrase'},headers=HEADERS).json()['must_change_password'] is False
        assert client.get('/api/admin/state').status_code==200
        assert client.get('/first-access',follow_redirects=False).headers['location']=='/'

def test_basic_cannot_bypass_first_access(tmp_path):
    repo = MemoryRepository()
    repo.state['admin_hash'] = 'bootstrap$' + hash_admin_password('admin')
    (tmp_path/'ca.crt').write_text('fixture')
    with TestClient(create_app(repo,tmp_path,monitor=False),base_url='https://central.example') as client:
        basic = {'Authorization':'Basic '+base64.b64encode(b'admin:admin').decode(),**HEADERS}
        assert client.get('/api/admin/state',headers=basic).status_code==403
        assert client.post('/api/admin/users',headers=basic,json={'username':'evil','password':'new-secure-passphrase'}).status_code==403
