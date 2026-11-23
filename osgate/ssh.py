"""Long-lived SSH transports, health checks and bounded reconnect."""
import asyncio
import logging
import random
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


async def connect_ssh(record: dict, settings):
    """Import at use-time to keep pure protocol tests independent of SSH library."""
    import asyncssh
    ssh_dir = settings.ssh_directory.resolve()
    hostkey_dir = settings.ssh_hostkeys_directory.resolve()
    def validate_path(raw, allowed):
        path = Path(raw).resolve(strict=True)
        if not any(path.is_relative_to(root) for root in allowed) or not path.is_file():
            raise ValueError('SSH credential path outside allowed directories')
        return str(path)
    key = validate_path(record['key_file'], (ssh_dir,))
    known_hosts = validate_path(record['known_hosts_file'], (ssh_dir, hostkey_dir))
    # AsyncSSH validates the server's public key against known_hosts, no TOFU bypass.
    return await asyncssh.connect(
        record['host'], port=record['port'], username=record['username'],
        client_keys=[key], known_hosts=known_hosts,
        connect_timeout=settings.ssh_connect_timeout,
        keepalive_interval=settings.ssh_keepalive_interval,
        keepalive_count_max=settings.ssh_keepalive_count_max,
        agent_path=None)


@dataclass
class State:
    record: dict
    connection: object = None
    status: str = 'CONNECTING'
    last_error: str = ''
    latency_ms: float | None = None
    failures: int = 0
    successes: int = 0
    reconnect_count: int = 0
    active_channels: int = 0
    task: asyncio.Task | None = None
    changed_at: float = 0
    verified: bool = False

    def ready(self) -> bool:
        return self.verified and self.status in ('ONLINE', 'DEGRADED') and self.connection is not None and not self.connection.is_closed()


class SSHManager:
    def __init__(self, db, settings, notify=None, connector=None):
        self.db = db
        self.settings = settings
        self.notify = notify
        self.connector = connector or connect_ssh
        self.states: dict[int, State] = {}
        self._stopping = False
        self._lock = asyncio.Lock()

    async def start(self):
        self._stopping = False
        await self.refresh()

    async def refresh(self):
        records = await asyncio.to_thread(self.db.servers)
        async with self._lock:
            keep = {r['id'] for r in records if r['enabled']}
            for sid in list(self.states):
                if sid not in keep:
                    await self._stop_state(self.states.pop(sid))
            for rec in records:
                if not rec['enabled']:
                    continue
                old = self.states.get(rec['id'])
                if old and old.record == rec:
                    continue
                if old:
                    await self._stop_state(old)
                state = State(record=rec)
                self.states[rec['id']] = state
                state.task = asyncio.create_task(self._maintain(state), name=f"ssh-{rec['id']}")

    async def _stop_state(self, state):
        if state.task:
            state.task.cancel()
        if state.connection is not None:
            state.connection.close()
        if state.task:
            await asyncio.gather(state.task, return_exceptions=True)
        state.status = 'DISABLED'

    async def stop(self):
        self._stopping = True
        async with self._lock:
            for state in self.states.values():
                await self._stop_state(state)
            self.states.clear()

    async def reconnect(self, server_id: int):
        async with self._lock:
            state = self.states.pop(server_id, None)
            if state:
                await self._stop_state(state)
        await self.refresh()

    async def _emit(self, category, message):
        # No secrets: only a server name and generic status, never exceptions with key paths.
        log.warning('%s: %s', category, message)
        try:
            await asyncio.to_thread(self.db.event, category, message)
        except Exception:
            log.exception('Could not save event')
        if self.notify:
            await self.notify(category, message)

    async def _maintain(self, state: State):
        delay = self.settings.ssh_reconnect_initial_delay
        try:
            while not self._stopping:
                conn = None
                try:
                    state.status = 'CONNECTING' if not state.reconnect_count else 'RECONNECTING'
                    state.reconnect_count += 1
                    conn = await self.connector(state.record, self.settings)
                    state.connection = conn
                    state.status = 'CONNECTING'
                    state.verified = False
                    state.failures = 0
                    state.successes = 0
                    state.last_error = ''
                    state.changed_at = time.monotonic()
                    delay = self.settings.ssh_reconnect_initial_delay
                    # Periodic real forwarded TCP probes (SSH socket existence alone is insufficient).
                    while not self._stopping and not conn.is_closed():
                        begin = time.monotonic()
                        try:
                            reader, writer = await asyncio.wait_for(
                                conn.open_connection(self.settings.health_test_host,
                                                     self.settings.health_test_port),
                                timeout=self.settings.health_check_timeout)
                            writer.close()
                            if self.settings.health_dns_enabled:
                                # Remote domain is resolved at the SSH exit, not locally.
                                _, dns_writer = await asyncio.wait_for(
                                    conn.open_connection(self.settings.health_dns_test_host,
                                                         self.settings.health_test_port),
                                    timeout=self.settings.health_check_timeout)
                                dns_writer.close()
                            state.latency_ms = round((time.monotonic() - begin) * 1000, 1)
                            state.successes += 1
                            state.failures = 0
                            if state.successes >= self.settings.health_success_threshold:
                                if not state.verified:
                                    await self._emit('SSH', f"{state.record['name']}: ONLINE")
                                state.verified = True
                                state.status = 'ONLINE'
                        except (Exception,) as exc:
                            if isinstance(exc, asyncio.CancelledError):
                                raise
                            state.failures += 1
                            state.successes = 0
                            state.last_error = type(exc).__name__
                            state.status = 'DEGRADED' if state.verified else 'CONNECTING'
                            if state.failures >= self.settings.health_failure_threshold:
                                state.status = 'OFFLINE'
                                state.verified = False
                                break
                        await asyncio.sleep(self.settings.health_check_interval)
                    if self._stopping:
                        break
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    # Exception class only, as transport errors may include sensitive paths.
                    state.last_error = type(exc).__name__
                    log.warning('SSH %s connection failed: %s', state.record['name'], type(exc).__name__)
                finally:
                    state.connection = None
                    state.verified = False
                    state.status = 'OFFLINE'
                    if conn:
                        conn.close()
                        await asyncio.gather(conn.wait_closed(), return_exceptions=True)
                if self._stopping:
                    break
                await self._emit('SSH', f"{state.record['name']}: OFFLINE")
                await asyncio.sleep(min(delay, self.settings.ssh_reconnect_max_delay) * random.uniform(0.85, 1.15))
                delay = min(delay * 2, self.settings.ssh_reconnect_max_delay)
        except asyncio.CancelledError:
            pass
        finally:
            state.connection = None
            state.status = 'DISABLED' if self._stopping else 'OFFLINE'

    def candidates(self):
        return [dict(**s.record, status=s.status, ready=s.ready(),
                     active_channels=s.active_channels, latency_ms=s.latency_ms,
                     last_error=s.last_error, reconnect_count=s.reconnect_count)
                for s in self.states.values()]

    async def open_channel(self, server_id: int, destination: str, port: int):
        state = self.states.get(server_id)
        if not state or not state.ready():
            raise ConnectionError('SSH server not ready')
        try:
            streams = await asyncio.wait_for(
                state.connection.open_connection(destination, port),
                timeout=self.settings.socks_connect_timeout)
            state.active_channels += 1
            return streams
        except Exception:
            state.failures += 1
            if state.failures >= self.settings.health_failure_threshold:
                state.status = 'OFFLINE'
            raise

    def release_channel(self, server_id):
        state = self.states.get(server_id)
        if state:
            state.active_channels = max(0, state.active_channels - 1)
