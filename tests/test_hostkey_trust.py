"""SSH server-host-key trust must be explicit, verified and fail-closed."""
import os
from pathlib import Path
import re

import asyncssh
import httpx
import pytest

from osgate.app import create_app
from osgate.database import SSHServer
from osgate.hostkey_trust import (
    HostKeyError, fingerprint_confirmed, host_identity, preview_host_key,
    store_host_key, verify_and_stage,
)
from osgate.ssh_onboarding import credential_path
from .test_socks5 import free_port


def test_store_trust_file_permissions_and_unmodified_existing_file(tmp_path):
    key = asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    initial = tmp_path / 'original'
    initial.write_text('KEEP_THIS_LINE\n')
    root = tmp_path / 'persistent' / 'ssh-hostkeys'
    path = store_host_key(key, 'gamma.example', 2222, root)
    assert path.exists() and path.parent == root
    assert path.stat().st_mode & 0o777 == 0o600
    assert root.stat().st_mode & 0o777 == 0o700
    assert path.read_text().startswith('[gamma.example]:2222 ssh-ed25519 ')
    assert initial.read_text() == 'KEEP_THIS_LINE\n'
    another = store_host_key(key, 'gamma.example', 2222, root)
    assert another != path  # never overwrite a previously trusted key
    assert credential_path(str(path), tmp_path, root) == path


@pytest.mark.parametrize('host,port', [
    ('host.example',22), ('78.17.160.67',22),('host.example',2222)
])
def test_host_identity(host,port):
    assert host_identity(host,port) == (host if port==22 else f'[{host}]:{port}')


@pytest.mark.parametrize('host,port', [
    ('host\nattacker',22),('x y',22),('',22),('host',0),('host',65536)
])
def test_invalid_host_never_accepted(host,port):
    with pytest.raises(HostKeyError):
        host_identity(host,port)


@pytest.mark.asyncio
async def test_preview_is_untrusted_and_fingerprint_must_match(tmp_path, monkeypatch):
    server_key = asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    expected = server_key.get_fingerprint()
    hits=[]
    async def fake_hostkey(host,port):
        hits.append((host,port))
        return server_key
    monkeypatch.setattr('osgate.hostkey_trust.asyncssh.get_server_host_key',fake_hostkey)
    key, fingerprint = await preview_host_key('host.example',2222)
    assert fingerprint == expected
    assert not fingerprint_confirmed(expected, '')
    assert not fingerprint_confirmed(expected, expected.lower())
    assert fingerprint_confirmed(expected, expected)
    class Config:
        ssh_hostkeys_directory=tmp_path/'trust'
        ssh_connect_timeout=1
    with pytest.raises(HostKeyError, match='не совпал'):
        await verify_and_stage('host.example',2222,'SHA256:BAD',Config())
    assert not Config.ssh_hostkeys_directory.exists()
    stored=await verify_and_stage('host.example',2222,expected,Config())
    assert stored.exists()
    assert len(hits)==3


@pytest.mark.asyncio
async def test_key_rotation_detected_between_preview_and_confirmation(tmp_path, monkeypatch):
    old=asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    new=asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    async def changed(host,port):
        return new
    monkeypatch.setattr('osgate.hostkey_trust.asyncssh.get_server_host_key',changed)
    class Config:
        ssh_hostkeys_directory=tmp_path/'trust'
        ssh_connect_timeout=1
    with pytest.raises(HostKeyError):
        await verify_and_stage('host.example',22,old.get_fingerprint(),Config())
    assert not Config.ssh_hostkeys_directory.exists()


@pytest.mark.asyncio
async def test_trust_existing_server_with_explicit_fingerprint_and_auth_failure(setup,monkeypatch):
    cfg,db=setup
    cfg.socks_port=await free_port()
    original=cfg.ssh_directory/'original_known_hosts'
    original.write_text('OLD TRUST\n')
    key_file=cfg.ssh_directory/'key'
    key_file.write_bytes(asyncssh.generate_private_key('ssh-ed25519').export_private_key())
    with db.session() as session:
        session.add(SSHServer(name='gamma',host='gamma.example',port=22,
                              username='ogsvnv',key_file=str(key_file),
                              known_hosts_file=str(original)))
    current=asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    async def remote_key(host,port,timeout):
        return current,current.get_fingerprint()
    async def no_auth(record,settings):
        raise asyncssh.PermissionDenied('denied')
    monkeypatch.setattr('osgate.web_v1.preview_host_key',remote_key)
    monkeypatch.setattr('osgate.hostkey_trust.preview_host_key',remote_key)
    monkeypatch.setattr('osgate.web_v1.probe_ssh',no_auth)
    app=create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49012)),
                base_url='http://127.0.0.1') as http:
            response=await http.get('/servers/1/hostkey')
            assert response.status_code==401
            login=await http.get('/login')
            token=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            await http.post('/login',data={'csrf':token,'username':'admin',
                                          'password':'secret-admin-password'})
            page=await http.get('/servers/1/hostkey')
            assert page.status_code==200
            assert current.get_fingerprint() in page.text
            assert 'НЕ ЯВЛЯЕТСЯ ДОВЕРЕННЫМ' in page.text
            token=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
            form={'csrf':token,'verified_fingerprint':current.get_fingerprint(),
                  'confirmed':'yes'}
            assert (await http.post('/servers/1/hostkey',
                         data={**form,'csrf':'invalid'})).status_code==403
            assert (await http.post('/servers/1/hostkey',
                         data={**form,'confirmed':''})).status_code==400
            invalid=await http.post('/servers/1/hostkey',
                         data={**form,'verified_fingerprint':'SHA256:fake'})
            assert invalid.status_code==200
            assert 'не принят' in invalid.text
            assert db.servers()[0]['known_hosts_file']==str(original)
            assert not cfg.ssh_hostkeys_directory.exists()
            success=await http.post('/servers/1/hostkey',data=form)
            assert success.status_code==200
            assert 'Ключ SSH-сервера подтверждён' in success.text
            assert 'PermissionDenied' in success.text
            now=db.servers()[0]['known_hosts_file']
            assert now!=str(original)
            assert original.read_text()=='OLD TRUST\n'
            assert os.path.isfile(now)
            assert 'gamma.example ssh-ed25519 ' in open(now).read()


@pytest.mark.asyncio
async def test_add_new_server_with_explicit_verified_hostkey(setup,monkeypatch):
    cfg,db=setup
    cfg.socks_port=await free_port()
    current=asyncssh.import_public_key(asyncssh.generate_private_key('ssh-ed25519').export_public_key())
    async def scan(host,port,timeout):
        return current,current.get_fingerprint()
    monkeypatch.setattr('osgate.hostkey_trust.preview_host_key',scan)
    monkeypatch.setattr('osgate.web.preview_host_key',scan)
    class Conn:
        async def open_connection(self,host,port):
            return None,type('W',(),{'close':lambda self:None})()
        def close(self): pass
        async def wait_closed(self): pass
    async def connect(record,settings):
        assert record['known_hosts_file'].startswith(str(cfg.ssh_hostkeys_directory))
        return Conn()
    monkeypatch.setattr('osgate.web.connect_ssh',connect)
    app=create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49013)),
                base_url='http://127.0.0.1') as http:
            login=await http.get('/login')
            token=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            await http.post('/login',data={'csrf':token,'username':'admin',
                                          'password':'secret-admin-password'})
            page=await http.get('/servers')
            token=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
            assert 'Показать SHA256-отпечаток' in page.text
            got=await http.post('/api/ssh/hostkey-preview',data={
                'csrf':token,'host':'gamma.example','port':'22'})
            assert got.json()['fingerprint']==current.get_fingerprint()
            fields=dict(name='new',host='gamma.example',port='22',
                        username='user',key_file='/ssh/key',known_hosts_file='/ssh/known_hosts',
                        priority='1',weight='1',csrf=token)
            rejected=await http.post('/servers/new',data={
                **fields,'confirm_hostkey':'yes','verified_fingerprint':'SHA256:fake'})
            assert rejected.status_code==200
            assert not db.servers()
            assert not cfg.ssh_hostkeys_directory.exists()
            created=await http.post('/servers/new',data={
                **fields,'confirm_hostkey':'yes',
                'verified_fingerprint':current.get_fingerprint()})
            assert created.status_code==303
            assert len(db.servers())==1
            trust=db.servers()[0]['known_hosts_file']
            assert Path(trust).is_file()
