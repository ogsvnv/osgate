"""One-time SSH public-key enrollment using an already authorized SSH password.

The password is transient: never persisted, logged, sent to templates or passed
to a shell command. SSH host-key verification is mandatory for both connections.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import shlex
import base64

import asyncssh


class EnrollmentError(Exception):
    """Safe, client-visible SSH enrollment failure."""


def credential_path(raw: str, directory: Path) -> Path:
    """Use only existing regular files in the configured SSH_DIRECTORY."""
    try:
        base = directory.resolve(strict=True)
        path = Path(raw).resolve(strict=True)
        if not path.is_relative_to(base) or not path.is_file():
            raise EnrollmentError("SSH-ключ и known_hosts должны находиться в SSH_DIRECTORY.")
    except (OSError, ValueError) as exc:
        raise EnrollmentError("SSH-ключ или known_hosts не найден.") from exc
    return path


def derive_public_key(private_key: Path) -> str:
    try:
        key = asyncssh.read_private_key(str(private_key))
    except (OSError, ValueError, asyncssh.KeyImportError) as exc:
        raise EnrollmentError(
            "Не удалось прочитать SSH-ключ. Нужен ключ без passphrase.") from exc
    public = key.export_public_key().decode("ascii").strip()
    # Only OpenSSH public keys, without embedded newline, quotes or shell syntax.
    fields = public.split()
    if (len(fields) < 2 or "\n" in public or "\r" in public
            or not fields[0].startswith(("ssh-", "ecdsa-", "sk-"))):
        raise EnrollmentError("Некорректный публичный SSH-ключ.")
    try:
        base64.b64decode(fields[1], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise EnrollmentError("Некорректный публичный SSH-ключ.") from exc
    return " ".join(fields[:2])


def installation_command(public_key: str) -> str:
    """Idempotent install, append-only: preserve existing authorized SSH keys."""
    if ("\n" in public_key or "\r" in public_key
            or len(public_key) > 16384
            or len(public_key.split()) != 2):
        raise EnrollmentError("Некорректный публичный SSH-ключ.")
    quoted = shlex.quote(public_key)
    return (
        "umask 077; "
        "mkdir -p \"$HOME/.ssh\" && chmod 700 \"$HOME/.ssh\" && "
        "touch \"$HOME/.ssh/authorized_keys\" && "
        "chmod 600 \"$HOME/.ssh/authorized_keys\" && "
        f"key={quoted} && ("
        "grep -Fqx -- \"$key\" \"$HOME/.ssh/authorized_keys\" || "
        "printf '\\n%s\\n' \"$key\" >> \"$HOME/.ssh/authorized_keys\")"
    )


async def enroll_public_key(record: dict, settings, password: str):
    """Authorize the configured OSGate key via a one-off password SSH session.

    The SSH server must explicitly allow password login for this user.
    OSGate never modifies sshd_config or disables host-key verification.
    """
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise EnrollmentError("Введите пароль пользователя SSH.")
    key = credential_path(record["key_file"], settings.ssh_directory)
    known_hosts = credential_path(record["known_hosts_file"], settings.ssh_directory)
    public_key = await asyncio.to_thread(derive_public_key, key)
    conn = None
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                record["host"],
                port=record["port"],
                username=record["username"],
                password=password,
                client_keys=[],
                agent_path=None,
                known_hosts=str(known_hosts),
                connect_timeout=settings.ssh_connect_timeout,
            ),
            timeout=settings.ssh_connect_timeout + 2,
        )
        result = await asyncio.wait_for(
            conn.run(installation_command(public_key), check=False),
            timeout=settings.ssh_connect_timeout + 5,
        )
        if result.exit_status != 0:
            raise EnrollmentError(
                "Удалённый сервер не разрешил записать ~/.ssh/authorized_keys.")
    except asyncssh.PermissionDenied as exc:
        raise EnrollmentError(
            "Сервер отклонил пароль SSH. Проверьте пароль и PasswordAuthentication. "
            "Если парольный вход запрещён, установите ключ через уже доверенный доступ.") from exc
    except asyncssh.HostKeyNotVerifiable as exc:
        raise EnrollmentError(
            "Не удалось проверить host key удалённого сервера. Сверьте known_hosts.") from exc
    except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
        raise EnrollmentError(
            "SSH-подключение не удалось. Проверьте порт, host key и разрешённый способ входа.") from exc
    finally:
        if conn is not None:
            conn.close()
            await conn.wait_closed()
