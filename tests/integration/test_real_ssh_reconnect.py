"""Opt-in real SSH reconnect/fail-closed test; aborts only client transport.

This test does not stop or modify the SSH daemon. Run only with explicit
OSGATE_E2E_* variables against an authorized server.
"""
"""Explicit, isolated real-server reconnect test; never modifies SSH server configuration."""
import asyncio, os, secrets, socket, tempfile, shutil
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory
from osgate.config import Settings
from osgate.database import Database, Client, SSHServer, hasher
from osgate.socks5 import SocksServer
from osgate.ssh import SSHManager, connect_ssh

async def wait_until(predicate, timeout=18, interval=.05):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(interval)

async def fetch(port, secret):
    p=await asyncio.create_subprocess_exec('curl','--silent','--show-error','--fail',
        '--max-time','12','--proxy',f'socks5h://127.0.0.1:{port}',
        '--proxy-user',f'probe:{secret}','https://api.ipify.org',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout,stderr=await p.communicate()
    return p.returncode,stdout.decode().strip(),stderr.decode().strip()[:100]

async def open_idle_channel(port, secret):
    reader,writer=await asyncio.open_connection('127.0.0.1',port)
    writer.write(b'\x05\x01\x02'); await writer.drain()
    assert await reader.readexactly(2)==b'\x05\x02'
    username=b'probe';pw=secret.encode()
    writer.write(bytes([1,len(username)])+username+bytes([len(pw)])+pw)
    await writer.drain()
    assert await reader.readexactly(2)==b'\x01\x00'
    dest=b'api.ipify.org'
    writer.write(bytes([5,1,0,3,len(dest)])+dest+(443).to_bytes(2,'big'))
    await writer.drain()
    response=await reader.readexactly(10)
    assert response[:2]==b'\x05\x00',response
    return reader,writer

async def main():
    required=('OSGATE_E2E_HOST','OSGATE_E2E_USERNAME','OSGATE_E2E_KEY_FILE',
              'OSGATE_E2E_KNOWN_HOSTS','OSGATE_E2E_EXPECTED_IP')
    if not all(os.environ.get(v) for v in required):
        pytest.skip('Opt-in real SSH reconnect test requires OSGATE_E2E_*')
    if not shutil.which('curl'):
        pytest.skip('curl binary unavailable')
    key=Path(os.environ['OSGATE_E2E_KEY_FILE']).resolve(strict=True)
    knownhosts=Path(os.environ['OSGATE_E2E_KNOWN_HOSTS']).resolve(strict=True)
    sshdir=key.parent
    assert knownhosts.parent==sshdir

    with tempfile.TemporaryDirectory(prefix='osgate-reconnect-') as d:
        with socket.socket() as s:
            s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        cfg=Settings(session_secret=secrets.token_hex(32),
            database_url='sqlite:///'+d+'/osgate.db',ssh_directory=sshdir,
            socks_host='127.0.0.1', socks_port=port,
            health_check_interval=.3, health_check_timeout=4,
            health_failure_threshold=2,health_success_threshold=1,
            ssh_connect_timeout=8,ssh_reconnect_initial_delay=.25,ssh_reconnect_max_delay=1)
        db=Database(cfg.database_url);db.initialize()
        password=secrets.token_urlsafe(20)
        with db.session() as session:
            session.add(Client(name='probe',username='probe',password_hash=hasher.hash(password),max_connections=10))
            session.add(SSHServer(name='remote',host=os.environ['OSGATE_E2E_HOST'],port=int(os.environ.get('OSGATE_E2E_PORT','22')),username=os.environ['OSGATE_E2E_USERNAME'],
                key_file=str(key),known_hosts_file=str(knownhosts),priority=1))
        gate=asyncio.Event()
        attempts=0
        async def gated_connect(rec,settings):
            nonlocal attempts
            attempts+=1
            if attempts>1:
                await gate.wait()
            return await connect_ssh(rec,settings)
        mgr=SSHManager(db,cfg,connector=gated_connect)
        proxy=SocksServer(db,mgr,cfg)
        await mgr.start()
        await proxy.start()
        try:
            await wait_until(lambda: any(s['ready'] for s in mgr.candidates()))
            before=await fetch(port,password)
            print('BEFORE:',before)
            assert before[0]==0 and before[1]==os.environ['OSGATE_E2E_EXPECTED_IP']
            reader,writer=await open_idle_channel(port,password)
            await wait_until(lambda: len(proxy.active)>=1)
            print('ACTIVE_BEFORE:',len(proxy.active))
            old_connection=next(iter(mgr.states.values())).connection
            print('ABORT_METHOD:',hasattr(old_connection,'abort'))
            if hasattr(old_connection,'abort'):
                old_connection.abort()
            else:
                old_connection.close()
            await wait_until(lambda: attempts>=2)
            print('DURING:',mgr.candidates()[0]['status'])
            during=await fetch(port,password)
            print('SOCKS_DURING:',during)
            assert during[0]!=0
            try:
                b=await asyncio.wait_for(reader.read(1),5)
                print('OLD_SESSION_CLOSED:',b==b'')
            except Exception as exc:
                print('OLD_SESSION_ERROR:',type(exc).__name__)
            await wait_until(lambda: len(proxy.active)==0 and all(s['active_channels']==0 for s in mgr.candidates()))
            print('CHANNEL_CLEANUP_OK: true')
            gate.set()
            await wait_until(lambda: any(s['ready'] and s['reconnect_count']>=2 for s in mgr.candidates()))
            after=await fetch(port,password)
            print('AFTER:',after)
            assert after[0]==0 and after[1]==os.environ['OSGATE_E2E_EXPECTED_IP']
            print('SUCCESS_REAL_RECONNECT')
            writer.close()
            try:await writer.wait_closed()
            except OSError:pass
        finally:
            gate.set()
            await proxy.stop()
            await mgr.stop()
            db.engine.dispose()
@pytest.mark.asyncio
async def test_real_ssh_transport_reconnect_and_cleanup():
    await main()
