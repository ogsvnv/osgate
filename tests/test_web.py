import re
import asyncio
import httpx
import pytest
from osgate.app import create_app
from osgate.database import SSHServer
from .test_socks5 import free_port


@pytest.mark.asyncio
async def test_admin_session_and_csrf(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 40000))
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1') as client:
            assert (await client.get('/api/status')).status_code == 401
            login = await client.get('/login')
            assert login.status_code == 200
            token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            denied = await client.post('/login', data={'csrf': token, 'username': 'admin', 'password': 'wrong'})
            assert 'Ошибка авторизации' in denied.text
            blocked = await client.post('/login', data={'username': 'admin', 'password': 'secret-admin-password'})
            assert blocked.status_code == 403
            allowed = await client.post('/login', data={'csrf': token, 'username': 'admin', 'password': 'secret-admin-password'})
            assert allowed.status_code == 303
            assert (await client.get('/api/status')).status_code == 200
            assert (await client.get('/clients')).status_code == 200
            assert (await client.post('/clients/new', data={'username': 'hacker'})).status_code == 403
            overview = await client.get('/')
            token = re.search(r'name="csrf" value="([^"]+)"', overview.text).group(1)
            changed = await client.post('/routing', data={'csrf': token, 'mode': 'round_robin'})
            assert changed.status_code == 303
            assert db.routing()['mode'] == 'round_robin'
            logged_out = await client.post('/logout', data={'csrf': token})
            assert logged_out.status_code == 303
            assert (await client.get('/api/status')).status_code == 401
