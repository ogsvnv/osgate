"""Explicit SSH server-host-key enrollment (never trust on first use silently).

The SSH handshake preview is UNTRUSTED and must be compared against a fingerprint
obtained independently (server console/another trusted administrative channel).
Accepted keys live in the persistent data directory, never modify /ssh keys.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
from pathlib import Path
import re
import tempfile

import asyncssh


class HostKeyError(Exception):
    """Safe public error, with no server content or sensitive paths."""


def host_identity(host: str, port: int) -> str:
    if not isinstance(host, str) or not host or len(host) > 253:
        raise HostKeyError("Некорректный SSH-хост.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", host) or '..' in host:
            raise HostKeyError("Некорректное имя SSH-хоста.")
    if type(port) is not int or not 1 <= port <= 65535:
        raise HostKeyError("Некорректный SSH-порт.")
    return f"[{host}]:{port}" if port != 22 else host


async def preview_host_key(host: str, port: int, timeout: float = 10):
    """Read the remote host key without trusting it; return key and fingerprint."""
    host_identity(host, port)
    try:
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(host, port),
            timeout=max(1, min(float(timeout), 30)),
        )
        if key is None:
            raise HostKeyError("Сервер не предоставил публичный host key.")
        public = key.export_public_key().decode('ascii').strip().split()
        if len(public) < 2:
            raise HostKeyError("Некорректный публичный ключ сервера.")
        return key, key.get_fingerprint('sha256')
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as exc:
        raise HostKeyError(
            "Не удалось получить SSH host key. Проверьте хост, порт и доступность SSH.") from exc


def fingerprint_confirmed(actual: str, typed: str) -> bool:
    # Require EXACT fingerprint typed by the administrator after out-of-band verification.
    return bool(typed and re.fullmatch(r"SHA256:[A-Za-z0-9+/=]{32,96}", typed)
                and typed == actual)


def store_host_key(key, host: str, port: int, directory: Path) -> Path:
    """Create a fresh 0600 file, no overwrite, in the writable /data trust store."""
    identity = host_identity(host, port)
    if directory.is_symlink():
        raise HostKeyError("Недопустимый каталог доверенных ключей.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = directory.resolve(strict=True)
    os.chmod(root, 0o700)
    parts = key.export_public_key().decode("ascii").strip().split()
    if len(parts) < 2 or any('\n' in x or '\r' in x for x in parts[:2]):
        raise HostKeyError("Некорректный публичный host key.")
    entry = identity + ' ' + ' '.join(parts[:2]) + '\n'
    fd, name = tempfile.mkstemp(prefix='host-', suffix='.known_hosts', dir=str(root))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as output:
            output.write(entry)
    except Exception:
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    return Path(name)


async def verify_and_stage(host: str, port: int, fingerprint: str, settings):
    """Re-fetch actual key and only stage if independently verified fingerprint matches."""
    key, actual = await preview_host_key(host, port, settings.ssh_connect_timeout)
    if not fingerprint_confirmed(actual, fingerprint):
        raise HostKeyError(
            "Отпечаток не совпал. Ключ не принят. Сверьте SHA256 через доверенный канал.")
    return await asyncio.to_thread(
        store_host_key, key, host, port, settings.ssh_hostkeys_directory,
    )
