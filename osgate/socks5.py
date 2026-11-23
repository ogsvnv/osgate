"""RFC 1928/1929 CONNECT implementation, intentionally no direct socket fallback."""
import asyncio
import ipaddress
import logging
import struct
import time
from dataclasses import dataclass, field
from .routing import Router

log = logging.getLogger(__name__)


def reply(code: int, bind_addr: str = '0.0.0.0', bind_port: int = 0) -> bytes:
    addr = ipaddress.ip_address(bind_addr)
    kind = 1 if addr.version == 4 else 4
    return bytes((5, code, 0, kind)) + addr.packed + struct.pack('!H', bind_port)


async def read_destination(reader):
    version, command, reserved, addr_type = await reader.readexactly(4)
    if version != 5 or reserved != 0:
        raise ValueError('Malformed SOCKS5 request')
    if addr_type == 1:
        host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
    elif addr_type == 4:
        host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
    elif addr_type == 3:
        length = (await reader.readexactly(1))[0]
        if not length:
            raise ValueError('Empty domain')
        host = (await reader.readexactly(length)).decode('ascii')
        if not host.isascii() or any(c in host for c in '\x00/\\'):
            raise ValueError('Invalid domain')
    else:
        raise TypeError('Address type not supported')
    port = struct.unpack('!H', await reader.readexactly(2))[0]
    if port == 0:
        raise ValueError('Port must not be zero')
    return command, host, port


@dataclass
class Tunnel:
    id: int
    client_id: int
    username: str
    destination: str
    port: int
    ssh_server_id: int
    started: float = field(default_factory=time.monotonic)
    uploaded: int = 0
    downloaded: int = 0
    task: asyncio.Task | None = None


class SocksServer:
    def __init__(self, db, ssh, settings):
        self.db = db
        self.ssh = ssh
        self.settings = settings
        self.router = Router()
        self.server = None
        self.active: dict[int, Tunnel] = {}
        self.counts: dict[int, int] = {}
        self._lock = asyncio.Lock()
        self._sequence = 0
        self.rejected = 0
        self.completed = 0

    async def start(self):
        self.server = await asyncio.start_server(self._handle, self.settings.socks_host,
                                                 self.settings.socks_port, backlog=256,
                                                 limit=64 * 1024)
        log.info('SOCKS5 listener started')

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        tasks = [x.task for x in self.active.values() if x.task and x.task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def disconnect(self, tunnel_id):
        entry = self.active.get(tunnel_id)
        if entry and entry.task:
            entry.task.cancel()
            return True
        return False

    async def _read_with_timeout(self, reader, length):
        return await asyncio.wait_for(reader.readexactly(length), self.settings.socks_connect_timeout)

    async def _auth(self, reader, writer):
        version, count = await self._read_with_timeout(reader, 2)
        if version != 5 or count == 0:
            return None
        methods = await self._read_with_timeout(reader, count)
        if 2 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return None
        writer.write(b'\x05\x02')
        await writer.drain()
        if (await self._read_with_timeout(reader, 1)) != b'\x01':
            return None
        username_len = (await self._read_with_timeout(reader, 1))[0]
        if not username_len:
            writer.write(b'\x01\x01'); await writer.drain()
            return None
        username = (await self._read_with_timeout(reader, username_len)).decode('utf-8')
        password_len = (await self._read_with_timeout(reader, 1))[0]
        password = (await self._read_with_timeout(reader, password_len)).decode('utf-8')
        account = await asyncio.to_thread(self.db.authenticate, username, password)
        writer.write(b'\x01\x00' if account else b'\x01\x01')
        await writer.drain()
        return account

    async def _pump(self, reader, writer, tunnel, direction):
        while True:
            data = await asyncio.wait_for(reader.read(65536), self.settings.socks_idle_timeout)
            if not data:
                if hasattr(writer, 'can_write_eof') and writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return
            writer.write(data)
            await writer.drain()  # backpressure
            if direction == 'upload':
                tunnel.uploaded += len(data)
            else:
                tunnel.downloaded += len(data)

    async def _handle(self, reader, writer):
        ident = None
        channel_writer = None
        tunnel = None
        try:
            async with asyncio.timeout(self.settings.socks_connect_timeout):
                client = await self._auth(reader, writer)
                if not client:
                    self.rejected += 1
                    return
                command, destination, port = await read_destination(reader)
                if command != 1:
                    writer.write(reply(7)); await writer.drain()
                    return
                async with self._lock:
                    if (len(self.active) >= self.settings.socks_max_connections or
                            self.counts.get(client['id'], 0) >= client['max_connections']):
                        writer.write(reply(1)); await writer.drain()
                        return
                    self.counts[client['id']] = self.counts.get(client['id'], 0) + 1
                    ident = client['id']
                settings = await asyncio.to_thread(self.db.routing)
                candidates = self.router.candidates(self.ssh.candidates(), settings, client)
                # A candidate must be live and connected. No local connect() is ever used.
                channel = None
                selected_id = None
                for candidate in candidates:
                    try:
                        channel = await self.ssh.open_channel(candidate['id'], destination, port)
                        selected_id = candidate['id']
                        break
                    except Exception:
                        log.warning('SSH forwarding refused: server_id=%s', candidate['id'])
                if channel is None:
                    writer.write(reply(1)); await writer.drain()
                    self.rejected += 1
                    return
                channel_reader, channel_writer = channel
                self._sequence += 1
                tunnel = Tunnel(id=self._sequence, client_id=client['id'],
                                username=client['username'], destination=destination,
                                port=port, ssh_server_id=selected_id,
                                task=asyncio.current_task())
                self.active[tunnel.id] = tunnel
                writer.write(reply(0)); await writer.drain()
            # Both halves run independently, allowing TCP half-closure.
            await asyncio.gather(self._pump(reader, channel_writer, tunnel, 'upload'),
                                 self._pump(channel_reader, writer, tunnel, 'download'))
        except asyncio.CancelledError:
            raise
        except (ValueError, TypeError, UnicodeDecodeError, asyncio.IncompleteReadError,
                asyncio.TimeoutError, ConnectionError, OSError) as exc:
            log.debug('SOCKS5 request ended: %s', type(exc).__name__)
            self.rejected += 1
        except Exception:
            log.exception('Unhandled SOCKS client error')
            self.rejected += 1
        finally:
            if channel_writer:
                channel_writer.close()
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
            if tunnel:
                self.active.pop(tunnel.id, None)
                self.ssh.release_channel(tunnel.ssh_server_id)
                self.completed += 1
                try:
                    await asyncio.to_thread(self.db.record_traffic,
                                            tunnel.client_id, tunnel.uploaded, tunnel.downloaded)
                except Exception:
                    log.exception('Could not persist traffic counters')
            if ident is not None:
                async with self._lock:
                    self.counts[ident] = max(0, self.counts.get(ident, 0) - 1)
