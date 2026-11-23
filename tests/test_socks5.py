import asyncio
import socket
import struct
import pytest
from osgate.socks5 import SocksServer
from osgate.ssh import SSHManager
from osgate.database import SSHServer


class FakeSSHConnection:
    def __init__(self, target_port):
        self.target_port = target_port
        self.closed = False
        self.calls = []

    def is_closed(self):
        return self.closed

    async def open_connection(self, host, port):
        self.calls.append((host, port))
        return await asyncio.open_connection('127.0.0.1', self.target_port)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return


async def echo(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    writer.close()


async def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


async def handshake(reader, writer, username='browser', password='client-password-123'):
    writer.write(b'\x05\x01\x02'); await writer.drain()
    assert await reader.readexactly(2) == b'\x05\x02'
    u, p = username.encode(), password.encode()
    writer.write(bytes((1, len(u))) + u + bytes((len(p),)) + p)
    await writer.drain()
    return await reader.readexactly(2)


async def connect_request(reader, writer, atyp=3, command=1):
    if atyp == 3:
        addr = bytes((len(b'example.test'),)) + b'example.test'
    elif atyp == 1:
        addr = socket.inet_aton('127.0.0.1')
    else:
        addr = socket.inet_pton(socket.AF_INET6, '::1')
    writer.write(bytes((5, command, 0, atyp)) + addr + struct.pack('!H', 1234))
    await writer.drain()
    return await reader.readexactly(10)


@pytest.mark.asyncio
async def test_socks_auth_routing_and_no_local_fallback(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    echoes = await asyncio.start_server(echo, '127.0.0.1', 0)
    echo_port = echoes.sockets[0].getsockname()[1]
    fake = FakeSSHConnection(echo_port)

    async def connector(record, settings):
        return fake

    manager = SSHManager(db, cfg, connector=connector)
    proxy = SocksServer(db, manager, cfg)
    await proxy.start()
    try:
        # Without SSH, SOCKS rejects; even though an echo service is locally reachable.
        r, w = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
        assert await handshake(r, w) == b'\x01\x00'
        assert (await connect_request(r, w))[1] != 0
        w.close(); await w.wait_closed()
        # Add a server; injected fake transport performs the forwarding.
        with db.session() as s:
            s.add(SSHServer(name='test', host='ssh.example', port=22, username='tester',
                            key_file='/ssh/key', known_hosts_file='/ssh/known_hosts'))
        await manager.start()
        for _ in range(30):
            if manager.candidates() and manager.candidates()[0]['ready']:
                break
            await asyncio.sleep(0.02)
        for atyp in (1, 3, 4):
            r, w = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
            assert await handshake(r, w) == b'\x01\x00'
            assert (await connect_request(r, w, atyp=atyp))[1] == 0
            w.write(b'example-content'); await w.drain()
            assert await r.readexactly(15) == b'example-content'
            w.close(); await w.wait_closed()
        assert ('example.test', 1234) in fake.calls
        r, w = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
        assert await handshake(r, w, password='bad') == b'\x01\x01'
        w.close(); await w.wait_closed()
        r, w = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
        assert await handshake(r, w) == b'\x01\x00'
        assert (await connect_request(r, w, command=2))[1] == 7
        w.close(); await w.wait_closed()
    finally:
        await proxy.stop()
        await manager.stop()
        echoes.close(); await echoes.wait_closed()


@pytest.mark.asyncio
async def test_auth_method_must_be_username_password(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    manager = SSHManager(db, cfg)
    proxy = SocksServer(db, manager, cfg)
    await proxy.start()
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
        writer.write(b'\x05\x01\x00'); await writer.drain()
        assert await reader.readexactly(2) == b'\x05\xff'
        writer.close(); await writer.wait_closed()
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_stopping_proxy_closes_incomplete_handshakes(setup):
    """Shutdown must not hang when clients leave SOCKS greetings unfinished."""
    cfg, db = setup
    cfg.socks_port = await free_port()
    proxy = SocksServer(db, SSHManager(db, cfg), cfg)
    await proxy.start()
    reader, writer = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
    writer.write(b'\x05')
    await writer.drain()
    await asyncio.wait_for(proxy.stop(), 2)
    try:
        assert await asyncio.wait_for(reader.read(1), 2) == b''
    except ConnectionResetError:
        pass  # Shutdown may reset a client with a partially sent greeting.
    writer.close()
    try:
        await writer.wait_closed()
    except ConnectionResetError:
        pass


@pytest.mark.asyncio
async def test_broken_ssh_releases_tunnel_and_cancels_sibling_pump(setup):
    """Abrupt SSH loss must close client and free connection counters."""
    cfg, db = setup
    cfg.socks_port = await free_port()
    cfg.health_check_interval = 0.05
    closing = asyncio.Event()

    async def breakable_target(reader, writer):
        await closing.wait()
        writer.close()
        await writer.wait_closed()

    target = await asyncio.start_server(breakable_target, '127.0.0.1', 0)
    port = target.sockets[0].getsockname()[1]
    fake = FakeSSHConnection(port)

    async def connector(record, settings):
        return fake

    with db.session() as session:
        session.add(SSHServer(name='test-breakage', host='ssh.example', port=22,
                              username='tester', key_file='/ssh/key',
                              known_hosts_file='/ssh/known_hosts'))
    manager = SSHManager(db, cfg, connector=connector)
    proxy = SocksServer(db, manager, cfg)
    await manager.start()
    await proxy.start()
    writer = None
    try:
        for _ in range(100):
            if any(s['ready'] for s in manager.candidates()):
                break
            await asyncio.sleep(0.01)
        reader, writer = await asyncio.open_connection('127.0.0.1', cfg.socks_port)
        assert await handshake(reader, writer) == b'\x01\x00'
        assert (await connect_request(reader, writer))[1] == 0
        for _ in range(100):
            if proxy.active:
                break
            await asyncio.sleep(0.01)
        assert len(proxy.active) == 1
        # Simulate losing the SSH transport and its forwarded stream.
        fake.close()
        closing.set()
        assert await asyncio.wait_for(reader.read(1), 2) == b''
        for _ in range(100):
            if not proxy.active and not any(proxy.counts.values()):
                break
            await asyncio.sleep(0.01)
        assert not proxy.active
        assert not any(proxy.counts.values())
        assert all(s['active_channels'] == 0 for s in manager.candidates())
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
        await proxy.stop()
        await manager.stop()
        target.close()
        await target.wait_closed()
