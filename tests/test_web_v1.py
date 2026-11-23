import re
import httpx
import pytest
from osgate.app import create_app
from osgate.database import Client, SSHServer
from .test_socks5 import free_port


@pytest.mark.asyncio
async def test_v1_client_admin_and_report(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 49100)),
                                     base_url='http://127.0.0.1') as h:
            login = await h.get('/login')
            token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            assert (await h.post('/login', data={'csrf': token, 'username': 'admin',
                                                'password': 'secret-admin-password'})).status_code == 303
            token = re.search(r'name="csrf" value="([^"]+)"', (await h.get('/')).text).group(1)
            with db.session() as s:
                s.add(SSHServer(name='test', host='old.example', username='user', port=22,
                                key_file='/ssh/key', known_hosts_file='/ssh/known_hosts'))
            assert '/ssh/key' not in (await h.get('/api/status')).text
            assert 'key_file' not in (await h.get('/api/status')).text
            assert '/ssh/key' not in (await h.get('/api/diagnostics')).text
            assert (await h.get('/api/events.csv')).status_code == 200
            assert (await h.get('/servers/1/edit')).status_code == 200
            assert (await h.get('/clients/1/edit')).status_code == 200
            assert (await h.get('/metrics')).status_code == 200
            assert (await h.get('/api/metrics')).status_code == 200
            assert (await h.post('/clients/1/edit', data={'csrf': token, 'name': 'Renamed',
                       'max_connections': '5', 'pinned_server_id': '1',
                       'allow_fallback': 'yes'})).status_code == 303
            with db.session() as s:
                c=s.get(Client,1)
                assert (c.name,c.max_connections,c.pinned_server_id,c.allow_fallback)==('Renamed',5,1,True)
            assert (await h.post('/clients/1/edit', data={'csrf': token, 'name': 'Bad',
                         'max_connections': '-1'})).status_code == 400
            assert (await h.post('/clients/1/password', data={'csrf': token,
                         'password': 'a-long-replacement-password'})).status_code == 200
            assert db.authenticate('browser', 'client-password-123') is None
            assert db.authenticate('browser', 'a-long-replacement-password')
            generated = await h.post('/clients/1/password', data={'csrf': token,
                                                                   'generate_password': 'yes'})
            assert generated.status_code == 200
            password = re.search(r'<code>([^<]+)</code>', generated.text).group(1)
            assert db.authenticate('browser', password)
            assert (await h.post('/admin/password', data={'csrf': token,
                     'current_password': 'bad', 'new_password': 'another-long-password'})).status_code == 403
            changed = await h.post('/admin/password', data={'csrf': token,
                      'current_password': 'secret-admin-password',
                      'new_password': 'another-long-password'})
            assert changed.status_code == 303
            assert db.verify_admin('admin', 'another-long-password')
            assert not db.verify_admin('admin', 'secret-admin-password')
            assert (await h.get('/api/status')).status_code == 401


@pytest.mark.asyncio
async def test_server_edit_validation_precedes_save(setup, monkeypatch):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1',49101)),
                                     base_url='http://127.0.0.1') as h:
            token = re.search(r'name="csrf" value="([^"]+)"', (await h.get('/login')).text).group(1)
            await h.post('/login', data={'csrf': token, 'username': 'admin', 'password': 'secret-admin-password'})
            token = re.search(r'name="csrf" value="([^"]+)"', (await h.get('/')).text).group(1)
            with db.session() as s:
                s.add(SSHServer(name='original', host='old.example', username='user', port=22,
                                key_file='/ssh/key', known_hosts_file='/ssh/known_hosts'))
            async def fail(*args):
                raise OSError('unreachable')
            monkeypatch.setattr('osgate.web_v1.probe_ssh', fail)
            result = await h.post('/servers/1/edit', data={'csrf': token,'name':'renamed',
                'host':'new.example', 'username':'user','port':'2222','priority':'1','weight':'1',
                'key_file':'/ssh/key','known_hosts_file':'/ssh/known_hosts'})
            assert result.status_code == 200
            with db.session() as s:
                assert s.get(SSHServer,1).name == 'original'
                assert s.get(SSHServer,1).host == 'old.example'
