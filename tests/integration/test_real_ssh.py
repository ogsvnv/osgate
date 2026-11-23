"""Opt-in real OpenSSH end-to-end test.

Set OSGATE_E2E_HOST, OSGATE_E2E_USERNAME, OSGATE_E2E_KEY_FILE,
OSGATE_E2E_KNOWN_HOSTS, OSGATE_E2E_EXPECTED_IP; optionally OSGATE_E2E_PORT.
Do not run this test against an SSH server without authorization.
"""
import asyncio
import os
import secrets
import shutil
import socket

import pytest

from osgate.config import Settings
from osgate.database import Client, Database, SSHServer, hasher
from osgate.socks5 import SocksServer
from osgate.ssh import SSHManager


async def curl_via_socks(port: int, password: str, timeout: int = 15):
    process = await asyncio.create_subprocess_exec(
        'curl', '--noproxy', '', '--silent', '--show-error', '--fail',
        '--max-time', str(timeout), '--proxy', f'socks5h://127.0.0.1:{port}',
        '--proxy-user', f'e2e:{password}', 'https://api.ipify.org',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    out, _ = await process.communicate()
    return process.returncode, out.decode().strip()


@pytest.mark.asyncio
async def test_real_openssh_forwarding_and_fail_closed(tmp_path):
    required = ('OSGATE_E2E_HOST', 'OSGATE_E2E_USERNAME', 'OSGATE_E2E_KEY_FILE',
                'OSGATE_E2E_KNOWN_HOSTS', 'OSGATE_E2E_EXPECTED_IP')
    if not all(os.environ.get(name) for name in required):
        pytest.skip('Real SSH integration requires explicit OSGATE_E2E_* configuration')
    if not shutil.which('curl'):
        pytest.skip('curl is required for the real SSH integration test')

    from pathlib import Path
    key = Path(os.environ['OSGATE_E2E_KEY_FILE']).resolve(strict=True)
    known_hosts = Path(os.environ['OSGATE_E2E_KNOWN_HOSTS']).resolve(strict=True)
    assert key.is_file() and known_hosts.is_file()
    assert key.parent == known_hosts.parent, 'Put SSH credentials in one protected directory'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    settings = Settings(
        session_secret=secrets.token_hex(32),
        database_url='sqlite:///' + str(tmp_path / 'osgate.db'),
        ssh_directory=key.parent, socks_host='127.0.0.1', socks_port=port,
        health_check_interval=1, health_check_timeout=5,
        health_success_threshold=1, health_failure_threshold=2,
    )
    db = Database(settings.database_url)
    db.initialize()
    secret = secrets.token_urlsafe(24)
    with db.session() as session:
        session.add(Client(name='e2e-test', username='e2e',
                           password_hash=hasher.hash(secret), max_connections=4))
        session.add(SSHServer(
            name='e2e-ssh', host=os.environ['OSGATE_E2E_HOST'],
            port=int(os.environ.get('OSGATE_E2E_PORT', '22')),
            username=os.environ['OSGATE_E2E_USERNAME'],
            key_file=str(key), known_hosts_file=str(known_hosts),
        ))
    manager = SSHManager(db, settings)
    proxy = SocksServer(db, manager, settings)
    await manager.start()
    try:
        await proxy.start()
        for _ in range(60):
            if any(s['ready'] for s in manager.candidates()):
                break
            await asyncio.sleep(0.25)
        assert any(s['ready'] for s in manager.candidates()), 'SSH unavailable'
        code, actual_ip = await curl_via_socks(port, secret)
        assert code == 0, 'SOCKS5/SSH internet request failed'
        assert actual_ip == os.environ['OSGATE_E2E_EXPECTED_IP'], 'Unexpected exit IP'
        await manager.stop()
        code, _ = await curl_via_socks(port, secret, timeout=5)
        assert code != 0, 'SOCKS5 traffic bypassed the disabled SSH transport'
    finally:
        await proxy.stop()
        await manager.stop()
        db.engine.dispose()
