"""Telegram Bot API must only be reachable over an existing ready SSH exit."""
import asyncio

import httpx
import pytest

from osgate.notifications import Notifier
from osgate.telegram_ssh_proxy import TelegramSSHProxy


class FakeSSH:
    def __init__(self, servers):
        self.servers = servers
        self.opened = []
        self.released = []
        self.failed = set()

    def candidates(self):
        return [dict(s) for s in self.servers]

    async def open_channel(self, server_id, host, port):
        self.opened.append((server_id, host, port))
        if server_id in self.failed:
            raise OSError('simulated SSH exit down')
        # This local echo simulates a remote TCP endpoint reached via SSH.
        return await asyncio.open_connection('127.0.0.1', self.target_port)

    def release_channel(self, server_id):
        self.released.append(server_id)


def ready(server_id, rtt=10, priority=100, ok=True):
    return dict(id=server_id, ready=ok, latency_ms=rtt,
                priority=priority, weight=1)


@pytest.mark.asyncio
async def test_no_ssh_means_no_http_client_or_direct_network(setup, monkeypatch):
    cfg, db = setup
    ssh = FakeSSH([ready(1, ok=False)])
    bot = Notifier(cfg)
    bot.bind_ssh(ssh, db)
    def fail_httpx(*args, **kwargs):
        raise AssertionError('httpx must not be called without verified SSH exit')
    monkeypatch.setattr(httpx, 'AsyncClient', fail_httpx)
    bot.token = '123456789:' + 'x'*35
    bot.chat_id = '123456789'
    assert await bot.test() is False
    assert ssh.opened == []


@pytest.mark.asyncio
async def test_proxy_restricts_destination_and_forwards_over_ssh():
    async def echo(reader, writer):
        try:
            while data := await reader.read(4096):
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    remote = await asyncio.start_server(echo, '127.0.0.1', 0)
    ssh = FakeSSH([ready(2)])
    ssh.target_port = remote.sockets[0].getsockname()[1]
    try:
        async with TelegramSSHProxy(ssh, 2) as proxy:
            r, w = await asyncio.open_connection('127.0.0.1', proxy.port)
            w.write(b'CONNECT example.org:443 HTTP/1.1\r\n\r\n')
            await w.drain()
            denied = await asyncio.wait_for(r.read(200), 2)
            assert b'403 Forbidden' in denied
            w.close()
            await w.wait_closed()
            assert not ssh.opened

            r, w = await asyncio.open_connection('127.0.0.1', proxy.port)
            w.write(b'CONNECT api.telegram.org:443 HTTP/1.1\r\n'
                    b'Host: api.telegram.org:443\r\n\r\n')
            await w.drain()
            allowed = await asyncio.wait_for(r.readuntil(b'\r\n\r\n'), 2)
            assert b'200 Connection Established' in allowed
            w.write(b'fake-tls-bytes')
            await w.drain()
            assert await asyncio.wait_for(r.readexactly(14), 2) == b'fake-tls-bytes'
            w.close()
            await w.wait_closed()
            await asyncio.sleep(0.05)
            assert ssh.opened == [(2, 'api.telegram.org', 443)]
            assert ssh.released == [2]
    finally:
        remote.close()
        await remote.wait_closed()


@pytest.mark.asyncio
async def test_notifier_attempts_ssh_in_preference_order_with_no_direct_fallback(setup, monkeypatch):
    cfg, db = setup
    ssh = FakeSSH([ready(1, rtt=40), ready(2, rtt=10),
                   ready(3, rtt=1, ok=False)])
    bot = Notifier(cfg)
    bot.bind_ssh(ssh, db)
    bot.token = '123456789:'+'x'*35
    bot.chat_id = '1234'
    with db.session() as session:
        from osgate.database import Routing
        session.get(Routing, 1).mode = 'min_rtt'

    real_http_client = httpx.AsyncClient
    clients = []
    class ClientStub:
        def __init__(self, *args, **kwargs):
            clients.append(kwargs)
            self.index = len(clients)
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            pass
        async def post(self, url, json):
            assert url.startswith('https://api.telegram.org/bot')
            assert json['chat_id'] == '1234'
            if self.index == 1:
                raise httpx.ConnectError('simulated SSH failure')
            return httpx.Response(200, json={'ok':True})

    monkeypatch.setattr(httpx,'AsyncClient',ClientStub)
    result = await bot.test()
    assert result is True
    assert len(clients) == 2
    assert all(c['trust_env'] is False for c in clients)
    assert all(c['proxy'].startswith('http://127.0.0.1:') for c in clients)
    assert len({c['proxy'] for c in clients}) == 2
    # Proves SSH preference uses RTT and offline servers are excluded
    candidates = await bot.ssh_candidates()
    assert [s['id'] for s in candidates] == [2, 1]
    assert real_http_client is not None


@pytest.mark.asyncio
async def test_manual_mode_has_no_fallback_to_other_ssh_servers(setup):
    cfg, db = setup
    ssh = FakeSSH([ready(1), ready(2)])
    bot=Notifier(cfg)
    bot.bind_ssh(ssh, db)
    with db.session() as session:
        from osgate.database import Routing
        route=session.get(Routing,1)
        route.mode='manual'
        route.manual_server_id=2
    assert [s['id'] for s in await bot.ssh_candidates()] == [2]
    ssh.servers[1]['ready'] = False
    assert await bot.ssh_candidates() == []


@pytest.mark.asyncio
async def test_httpx_https_uses_connect_via_ssh_not_direct():
    # The SSH test transport connects to a local echo server, not Telegram.
    # HTTPX must first use the proxy CONNECT tunnel; the subsequent TLS
    # handshake fails on purpose because the echo server is not TLS.
    async def echo(reader, writer):
        try:
            while chunk := await reader.read(4096):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()
    remote=await asyncio.start_server(echo,'127.0.0.1',0)
    ssh=FakeSSH([ready(1)])
    ssh.target_port=remote.sockets[0].getsockname()[1]
    try:
        async with TelegramSSHProxy(ssh,1) as proxy:
            async with httpx.AsyncClient(timeout=3,trust_env=False,
                proxy=f'http://127.0.0.1:{proxy.port}') as client:
                with pytest.raises(httpx.HTTPError):
                    await client.post('https://api.telegram.org/botFAKE/sendMessage',
                        json={'chat_id':'1','text':'test'})
            await asyncio.sleep(0.05)
            assert ssh.opened == [(1,'api.telegram.org',443)]
    finally:
        remote.close()
        await remote.wait_closed()
