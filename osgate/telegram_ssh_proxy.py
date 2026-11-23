"""Loopback-only, short-lived HTTPS CONNECT proxy over an already verified SSH transport.

Never opens a direct Internet socket. httpx performs normal TLS validation and
remote DNS resolution is delegated to the SSH exit via AsyncSSH forwarding.
Only CONNECT api.telegram.org:443 is accepted, no arbitrary destinations.
"""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger(__name__)


class TelegramSSHProxy:
    def __init__(self, ssh, server_id: int):
        self.ssh = ssh
        self.server_id = server_id
        self.listener = None
        self.connections: set[asyncio.Task] = set()
        self.port = None

    async def __aenter__(self):
        self.listener = await asyncio.start_server(
            self._handle, '127.0.0.1', 0, limit=8192)
        self.port = self.listener.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_):
        self.listener.close()
        await self.listener.wait_closed()
        for task in tuple(self.connections):
            task.cancel()
        await asyncio.gather(*self.connections, return_exceptions=True)

    @staticmethod
    async def _copy(reader, writer):
        try:
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self.connections.add(task)
        remote_writer = None
        try:
            # This temporary proxy only handles Telegram CONNECT requests.
            request = await asyncio.wait_for(reader.readline(), timeout=5)
            if request != b'CONNECT api.telegram.org:443 HTTP/1.1\r\n':
                writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                await writer.drain()
                return
            # Consume CONNECT headers, reject oversize or malformed requests.
            count = len(request)
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                count += len(line)
                if count > 8192 or not line:
                    return
                if line == b'\r\n':
                    break
            remote_reader, remote_writer = await self.ssh.open_channel(
                self.server_id, 'api.telegram.org', 443)
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            left = asyncio.create_task(self._copy(reader, remote_writer))
            right = asyncio.create_task(self._copy(remote_reader, writer))
            try:
                done, pending = await asyncio.wait(
                    (left, right), return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*done, *pending, return_exceptions=True)
            finally:
                for t in (left, right):
                    if not t.done():
                        t.cancel()
                await asyncio.gather(left, right, return_exceptions=True)
        except (OSError, ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            log.debug('Telegram SSH forwarding failed, server_id=%s', self.server_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never log CONNECT headers, tokenized HTTP URLs or credentials.
            log.warning('Telegram SSH forwarding failed, server_id=%s', self.server_id)
        finally:
            if remote_writer:
                remote_writer.close()
                self.ssh.release_channel(self.server_id)
            writer.close()
            self.connections.discard(task)
