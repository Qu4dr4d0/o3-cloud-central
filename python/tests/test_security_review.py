"""Regression checks for the pre-pilot security and performance review."""
import asyncio
import logging
import threading
import time

import pytest

from edgehub.central import APIError
from edgehub.log_security import InstallationTokenFilter, install_log_filters
from test_central import lab
from test_central_auth import accounts, login, HEADERS


def test_login_lockout_does_not_block_valid_sessions_or_other_buckets(accounts):
    client, _, app = accounts
    central = app.state.central
    central.failures['enrollment:testclient'] = [time.monotonic()] * 21
    assert login(client).status_code == 200
    central.failures['auth:testclient'] = [time.monotonic()] * 21
    assert client.get('/api/auth/me').status_code == 200
    assert client.get('/api/admin/state').status_code == 200
    assert client.get('/').status_code == 200
    assert client.post('/api/auth/logout',json={},headers=HEADERS).status_code == 200
    assert login(client).status_code == 429


@pytest.mark.asyncio
async def test_password_workers_remain_bounded_when_request_cancelled(lab):
    _, _, central = lab
    started = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = peak = 0
    def expensive():
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == 2: started.set()
        try: release.wait(3)
        finally:
            with lock: active -= 1
        return True
    first = asyncio.create_task(central.password_work(expensive))
    second = asyncio.create_task(central.password_work(expensive))
    try:
        assert await asyncio.to_thread(started.wait, 2)
        first.cancel()
        with pytest.raises(asyncio.CancelledError): await first
        with pytest.raises(APIError) as error:
            await central.password_work(expensive)
        assert error.value.status == 429 and peak == 2
    finally:
        release.set()
        await asyncio.gather(second, return_exceptions=True)
        await asyncio.sleep(.05)
    assert await central.password_work(lambda: True)
    assert active == 0 and peak == 2


@pytest.mark.asyncio
async def test_slow_and_deep_json_requests_fail_with_client_errors(lab, monkeypatch):
    _, _, central = lab
    import edgehub.central as core
    monkeypatch.setattr(core,'BODY_TIMEOUT',.01)
    class Slow:
        headers={'content-type':'application/json'}
        async def stream(self):
            yield b'{'
            await asyncio.sleep(1)
            yield b'}'
    with pytest.raises(APIError) as error: await central.body(Slow(),set())
    assert error.value.status == 408
    class Deep:
        headers={'content-type':'application/json'}
        async def stream(self): yield b'{"nested":'*1100+b'0'+b'}'*1100
    with pytest.raises(APIError) as error: await central.body(Deep(),{'nested'})
    assert error.value.status == 400


def test_http_logs_redact_installation_tokens_but_preserve_diagnostics():
    token='A'*43
    for route in ('/api/install/pfsense/'+token+'/package','/install/windows/'+token+'/installer.exe'):
        record=logging.LogRecord('uvicorn.access',20,__file__,1,'%s - "%s %s HTTP/%s" %d',('127.0.0.1','GET',route,'1.1',200),None)
        assert InstallationTokenFilter().filter(record)
        message=record.getMessage()
        assert token not in message and '[REDACTED]' in message and '200' in message
    record=logging.LogRecord('aiohttp.access',20,__file__,1,'GET /install/windows/'+token,(),None)
    InstallationTokenFilter().filter(record)
    assert token not in record.getMessage()
    install_log_filters();install_log_filters()
    assert sum(isinstance(f,InstallationTokenFilter) for f in logging.getLogger('uvicorn.access').filters)==1


def test_state_poll_uses_one_database_snapshot(accounts,monkeypatch):
    client,repository,_=accounts
    assert login(client).status_code == 200
    original=repository.read
    calls=0
    def counted():
        nonlocal calls
        calls+=1
        return original()
    monkeypatch.setattr(repository,'read',counted)
    assert client.get('/api/admin/state').status_code==200
    assert calls==1
