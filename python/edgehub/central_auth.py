"""Browser sessions and management accounts, persisted transactionally in SQL."""
import base64
import binascii
import hmac
import re
import secrets
from datetime import timedelta

from fastapi import Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .central import APIError, digest, now, parse_time, stamp
from .crypto import hash_admin_password
from . import central as core

COOKIE = '__Host-o3_session'
SESSION_SECONDS = 12 * 60 * 60
USERNAME = re.compile(r'[a-z0-9][a-z0-9._-]{2,63}')


def password_hash(state, username):
    return state['admin_hash'] if username == 'admin' else state.get('users', {}).get(username, {}).get('password_hash', '')


def must_change_password(state, username):
    return username == 'admin' and state['admin_hash'].startswith('bootstrap$')


def csrf(request):
    if request.headers.get('x-edgehub-request') != '1':
        raise APIError(403, 'cabeçalho de segurança obrigatório')
    origin = request.headers.get('origin', '')
    if origin and origin != 'https://' + request.headers.get('host', ''):
        raise APIError(403, 'origem inválida')


def session_user(state, raw):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', raw or ''):
        return None
    session = state.get('sessions', {}).get(digest(raw))
    if not session:
        return None
    expiry = parse_time(session.get('expires'))
    credential = password_hash(state, session.get('username'))
    if expiry and expiry > now() and credential and hmac.compare_digest(session.get('credential', ''), digest(credential)):
        return session['username']
    return None


async def verify_password(central, request, hashed, password):
    central.rate(request, bucket='auth')
    address = request.client.host if request.client else 'unknown'
    pending = central.auth_inflight.get(address, 0)
    if pending + len(central.failures.get('auth:'+address, [])) >= 20:
        raise APIError(429, 'aguarde antes de tentar novamente')
    if len(password.encode()) > 256:
        return False
    central.auth_inflight[address] = pending + 1
    try:
        return await central.password_work(core.check_admin_password, hashed, password)
    finally:
        remaining = central.auth_inflight[address] - 1
        if remaining: central.auth_inflight[address] = remaining
        else: del central.auth_inflight[address]


async def authenticate(central, request, *, allow_basic=True):
    state = await central.read()
    raw = request.cookies.get(COOKIE)
    username = session_user(state, raw)
    # Basic remains available to existing administration tooling; browser
    # pages require a session and never send a Basic authentication challenge.
    if not username and allow_basic and not raw:
        try:
            scheme, encoded = request.headers.get('authorization', '').split(' ', 1)
            if scheme.lower() != 'basic': raise ValueError()
            user, password = base64.b64decode(encoded, validate=True).decode().split(':', 1)
        except (ValueError, UnicodeError, binascii.Error):
            user, password = '', ''
        if user == 'admin' or USERNAME.fullmatch(user):
            hashed = password_hash(state, user)
            # Unknown accounts perform the same expensive check as known ones.
            valid = await verify_password(central, request, hashed or state['admin_hash'], password)
            if hashed and valid: username = user
    if not username:
        # Anonymous page loads do not consume the password-attempt budget.
        if request.headers.get('authorization'): central.rate(request, True, bucket='auth')
        raise APIError(401, 'Entre novamente para acessar o painel.')
    if request.method not in ('GET', 'HEAD'): csrf(request)
    request.state.username = username
    request.state.auth_state = state
    if must_change_password(state, username) and request.url.path not in (
            '/first-access', '/api/auth/me', '/api/auth/logout', '/api/admin/account/password'):
        raise APIError(403, 'Troque a senha inicial antes de acessar a central.')
    return username


def register_routes(app, central):
    @app.get('/login')
    async def login_page(request: Request):
        state = await central.read()
        username = session_user(state, request.cookies.get(COOKIE))
        if username:
            return RedirectResponse('/first-access' if must_change_password(state, username) else '/', status_code=303)
        return FileResponse(central.web / 'login.html', media_type='text/html')

    @app.get('/first-access')
    async def first_access(request: Request):
        try:
            username = await authenticate(central, request, allow_basic=False)
        except APIError as error:
            if error.status == 401:
                return RedirectResponse('/login', status_code=303)
            raise
        if not must_change_password(request.state.auth_state, username):
            return RedirectResponse('/', status_code=303)
        return FileResponse(central.web / 'first-access.html', media_type='text/html')

    @app.post('/api/auth/login')
    async def login(request: Request):
        csrf(request)
        central.rate(request, bucket='auth')
        body = await central.body(request, {'username', 'password'})
        user, password = body.get('username'), body.get('password')
        if not isinstance(user, str) or not isinstance(password, str):
            raise APIError(400, 'Informe usuário e senha.')
        user = user.strip().lower()
        if not USERNAME.fullmatch(user) or not 1 <= len(password.encode()) <= 256:
            central.rate(request, True, bucket='auth')
            raise APIError(401, 'Usuário ou senha incorretos.')
        state = await central.read()
        hashed = password_hash(state, user)
        valid = await verify_password(central, request, hashed or state['admin_hash'], password)
        if not hashed or not valid:
            central.rate(request, True, bucket='auth')
            raise APIError(401, 'Usuário ou senha incorretos.')
        raw = secrets.token_urlsafe(32)
        previous = request.cookies.get(COOKIE, '')
        def save(current):
            if password_hash(current, user) != hashed:
                raise APIError(401, 'Usuário ou senha incorretos.')
            sessions = {key:value for key,value in current.get('sessions', {}).items()
                        if (parse_time(value.get('expires')) or now()) > now() and key != digest(previous)
                        and value.get('credential') == digest(password_hash(current, value['username']))}
            if len(sessions) >= 4096:
                raise APIError(429, 'Limite de sessões atingido. Tente novamente mais tarde.')
            sessions[digest(raw)] = {'username':user, 'expires':stamp(now() + timedelta(seconds=SESSION_SECONDS)), 'credential':digest(hashed)}
            current['sessions'] = sessions
        await central.tx(save)
        response = JSONResponse({'username':user, 'must_change_password':must_change_password(state, user)})
        response.set_cookie(COOKIE, raw, max_age=SESSION_SECONDS, secure=True, httponly=True, samesite='strict', path='/')
        return response

    @app.get('/api/auth/me')
    async def me(request: Request):
        return {'username':await central.admin(request)}

    @app.post('/api/auth/logout')
    async def logout(request: Request):
        await central.admin(request)
        await central.body(request, set())
        hashed = digest(request.cookies.get(COOKIE, ''))
        await central.tx(lambda state: state.get('sessions', {}).pop(hashed, None))
        response = JSONResponse({'ok':True})
        response.delete_cookie(COOKIE, path='/', secure=True, httponly=True, samesite='strict')
        return response

    @app.get('/api/admin/users')
    async def list_users(request: Request):
        await central.admin(request)
        state = request.state.auth_state
        return {'users':[{'username':'admin', 'created':None}] +
                [{'username':name, 'created':account['created']} for name,account in sorted(state.get('users', {}).items())]}

    @app.post('/api/admin/users')
    async def add_user(request: Request):
        await central.admin(request)
        body = await central.body(request, {'username', 'password'})
        username, password = body.get('username'), body.get('password')
        if not isinstance(username, str) or not isinstance(password, str):
            raise APIError(400, 'Informe usuário e senha.')
        username = username.strip().lower()
        if not USERNAME.fullmatch(username):
            raise APIError(400, 'Use de 3 a 64 caracteres: letras, números, ponto, hífen ou sublinhado.')
        if len(password) < 12 or len(password.encode()) > 256:
            raise APIError(400, 'Use uma senha com pelo menos 12 caracteres e no máximo 256 bytes.')
        hashed = await central.password_work(hash_admin_password, password)
        created = stamp()
        def create(state):
            if username == 'admin' or username in state.get('users', {}):
                raise APIError(409, 'Este nome de usuário já está cadastrado.')
            if len(state.get('users', {})) >= 256:
                raise APIError(400, 'Limite de usuários atingido.')
            state.setdefault('users', {})[username] = {'password_hash':hashed, 'created':created}
        await central.tx(create)
        return {'username':username, 'created':created}
