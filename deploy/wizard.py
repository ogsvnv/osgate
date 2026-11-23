#!/usr/bin/env python3
"""OSGate deployment wizard. Python stdlib only; no hidden network changes.

Run from a trusted checkout with: sudo ./install.sh
All secrets are written with restricted permissions and never passed as arguments.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SYSTEM_ROOT = Path("/opt/osgate")
SYSTEM_ENV = Path("/etc/osgate/osgate.env")
SYSTEM_SSH = Path("/etc/osgate/ssh")
EXCLUDED = {".git", ".venv", ".env", ".pytest_cache", "__pycache__", "data", "ssh", "backups"}


class InstallError(Exception):
    pass


def info(message: str):
    print(f"  ✓ {message}", flush=True)


def section(message: str):
    print(f"\n━━━ {message} ━━━", flush=True)


def run(*args: str, cwd: Path | None = None, capture=False, check=True):
    command = [str(x) for x in args]
    try:
        return subprocess.run(
            command, cwd=str(cwd) if cwd else None, check=check,
            text=True, capture_output=capture,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise InstallError(f"Команда завершилась ошибкой: {command[0]} "
                           f"({' '.join(command[1:3])})") from exc


def require_commands(*commands: str):
    missing = [command for command in commands if not shutil.which(command)]
    if missing:
        raise InstallError("Отсутствуют программы: " + ", ".join(missing))


def require_root():
    if os.geteuid() != 0:
        raise InstallError("Для установки нужны права администратора: sudo ./install.sh")


def ask(label: str, default: str = "") -> str:
    value = input(f"{label}" + (f" [{default}]" if default else "") + ": ").strip()
    return value or default


def yesno(label: str, default=False) -> bool:
    hint = "Д/н" if default else "д/Н"
    value = input(f"{label} [{hint}]: ").strip().lower()
    if not value:
        return default
    if value in ("д", "да", "y", "yes"):
        return True
    if value in ("н", "нет", "n", "no"):
        return False
    raise InstallError("Введите «да» или «нет».")


def port_value(raw: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise InstallError("Порт должен быть числом.") from exc
    if not 1 <= port <= 65535:
        raise InstallError("Порт должен быть от 1 до 65535.")
    return port


def user_value(raw: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", raw):
        raise InstallError("Некорректное имя пользователя (латинские буквы/цифры/_/./-).")
    return raw


def host_value(raw: str) -> str:
    if not raw or len(raw) > 253 or not re.fullmatch(r"[A-Za-z0-9.:_-]+", raw):
        raise InstallError("Некорректный адрес SSH-хоста.")
    if raw.startswith("-") or raw.startswith(".") or ".." in raw:
        raise InstallError("Некорректный адрес SSH-хоста.")
    return raw


def unused_local_port(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise InstallError(f"Порт 127.0.0.1:{port} уже занят.") from exc


def bind_address(raw: str) -> str:
    """Only IPv4 listener addresses. Hostnames can resolve to unexpected interfaces."""
    try:
        return str(ipaddress.IPv4Address(raw))
    except ipaddress.AddressValueError as exc:
        raise InstallError("Укажите действительный IPv4-адрес интерфейса.") from exc


def interface_addresses() -> set[str]:
    """Collect local interface IPv4 addresses using the OS ip utility, if present."""
    addresses = {"127.0.0.1", "0.0.0.0"}
    if not shutil.which("ip"):
        return addresses
    result = run("ip", "-o", "-4", "addr", "show", capture=True, check=False)
    for match in re.finditer(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+", result.stdout):
        addresses.add(match.group(1))
    return addresses


def validate_socks_bind(raw: str, *, require_local=True) -> str:
    address = bind_address(raw)
    if require_local and address not in interface_addresses():
        raise InstallError(
            f"Адрес {address} не назначен ни одному интерфейсу сервера. "
            "Выберите адрес из 'ip -4 addr'.")
    return address


def select_socks_access() -> str:
    """Explicit listening policy for SOCKS5; admin panel stays loopback-only."""
    section("Доступность SOCKS5-прокси")
    print("1 — Только на сервере (127.0.0.1), рекомендуется")
    print("2 — Через все интерфейсы (0.0.0.0) — доступ извне")
    print("3 — Через указанный IPv4-адрес интерфейса")
    choice = ask("Режим SOCKS5", "1")
    if choice == "1":
        return "127.0.0.1"
    if choice == "2":
        print("ВНИМАНИЕ: SOCKS5 станет доступен по сети. "
              "Авторизация обязательна, ограничьте доступ firewall/ACL. "
              "Docker может обходить правила UFW через NAT; проверяйте DOCKER-USER.")
        if not yesno("Подтвердить публикацию SOCKS5 на всех интерфейсах?", False):
            raise InstallError("Публикация SOCKS5 отменена.")
        return "0.0.0.0"
    if choice == "3":
        address = validate_socks_bind(ask("Локальный IPv4 интерфейса"))
        if address != "127.0.0.1":
            print(f"SOCKS5 будет доступен через интерфейс {address}; проверьте firewall.")
            if not yesno(f"Разрешить прослушивание {address}?", False):
                raise InstallError("Настройка доступа отменена.")
        return address
    raise InstallError("Выберите режим доступа 1, 2 или 3.")


def check_bind_port(address: str, port: int):
    """Check only the interface that will listen, not an unrelated loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((address, port))
        except OSError as exc:
            raise InstallError(f"Нельзя занять {address}:{port}. Проверьте интерфейс и порт.") from exc


def atomic_secret(path: Path, content: str, replace=False):
    if path.exists() and not replace:
        raise InstallError(f"Файл уже существует: {path}. Данные не перезаписаны.")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".osgate-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(content)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def set_env_values(content: str, updates: dict[str, str]) -> str:
    """Edit allowlisted single-line env values, preserving other existing options."""
    for key, value in updates.items():
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or "\n" in value or "\r" in value:
            raise InstallError("Недопустимый параметр конфигурации.")
        replacement = f"{key}={value}"
        pattern = rf"(?m)^{re.escape(key)}=.*$"
        if re.search(pattern, content):
            content = re.sub(pattern, lambda _: replacement, content)
        else:
            content = content.rstrip() + "\n" + replacement + "\n"
    return content


def check_health(port: int, attempts=30, pause=1.0) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(attempts):
        try:
            with opener.open(f"http://127.0.0.1:{port}/healthz", timeout=1.0) as response:
                if response.status == 200:
                    return True
        except Exception:
            time.sleep(pause)
    return False


def default_key() -> str:
    username = os.environ.get("SUDO_USER") if os.geteuid() == 0 else None
    try:
        home = Path(pwd.getpwnam(username).pw_dir) if username else Path.home()
    except KeyError:
        home = Path.home()
    for name in ("id_ed25519", "id_rsa"):
        candidate = home / ".ssh" / name
        if candidate.is_file():
            return str(candidate)
    return ""


def identity_lookup(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def fetch_host_keys(host: str, port: int) -> str:
    require_commands("ssh-keyscan", "ssh-keygen")
    result = run("ssh-keyscan", "-T", "8", "-p", str(port), host, capture=True, check=False)
    keys = "\n".join(row for row in result.stdout.splitlines()
                     if row and not row.startswith("#"))
    if not keys:
        raise InstallError("Не удалось получить SSH host keys. Проверьте сеть/порт.")
    with tempfile.TemporaryDirectory(prefix="osgate-hostkey-") as tmp:
        candidate = Path(tmp) / "known_hosts"
        atomic_secret(candidate, keys + "\n")
        fingerprint = run("ssh-keygen", "-lf", str(candidate), capture=True).stdout.strip()
    section("Проверка подлинности SSH-сервера")
    print(fingerprint)
    print("Сверьте SHA256 fingerprint с сервером по доверенному каналу.")
    if ask('После сверки введите слово ДОВЕРЯЮ (иначе отмена)') != "ДОВЕРЯЮ":
        raise InstallError("Ключ сервера не подтверждён, установка SSH-настроек отменена.")
    return keys + "\n"


def trusted_host_keys(host: str, port: int, source: Path | None) -> str:
    lookup = identity_lookup(host, port)
    if source and source.is_file():
        result = run("ssh-keygen", "-F", lookup, "-f", str(source),
                     capture=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            # An existing known_hosts entry is already trusted by its owner.
            return source.read_text(encoding="utf-8")
    return fetch_host_keys(host, port)


def copy_secret(source: Path, target: Path, uid: int, gid: int, mode=0o600):
    if not source.is_file() or source.is_symlink():
        raise InstallError(f"SSH-ключ не найден или является ссылкой: {source}")
    source_data = source.read_bytes()
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or target.read_bytes() != source_data:
            raise InstallError(f"Нельзя автоматически заменить существующий SSH-ключ: {target}")
        os.chown(target, uid, gid)
        os.chmod(target, mode)
        return
    fd, temp = tempfile.mkstemp(prefix=".osgate-key-", dir=str(target.parent))
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb") as f:
            f.write(source_data)
        os.replace(temp, target)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def ssh_setup(target: Path, uid: int, gid: int, runtime_root: str):
    """Optional interactive SSH configuration; never accepts host keys silently."""
    if not yesno("Настроить SSH-сервер сейчас?", default=False):
        return None
    host = host_value(ask("SSH-хост/IP (например, park.example.com)"))
    port = port_value(ask("SSH-порт", "22"))
    username = user_value(ask("SSH-пользователь", os.environ.get("SUDO_USER", "root")))
    name = ask("Название сервера в OSGate", "primary")[:120]
    key_raw = ask("Путь к существующему SSH-ключу", default_key())
    key = Path(key_raw).expanduser()
    if not key.is_file():
        raise InstallError("SSH-ключ не найден. Создайте ключ и добавьте его публичную часть на SSH-сервер.")
    if target.is_symlink():
        raise InstallError("SSH-каталог не должен быть символической ссылкой.")
    # Verify the remote host BEFORE copying any private key to a new location.
    source_known = key.parent / "known_hosts"
    known = trusted_host_keys(host, port, source_known)
    target.mkdir(parents=True, exist_ok=True)
    os.chown(target, uid, gid)
    os.chmod(target, 0o700)
    dest_key = target / "id_ed25519"
    dest_known = target / "known_hosts"
    if dest_known.is_symlink():
        raise InstallError("SSH known_hosts не должен быть символической ссылкой.")
    copy_secret(key, dest_key, uid, gid)
    if dest_known.exists() and dest_known.is_symlink():
        raise InstallError("SSH known_hosts не должен быть символической ссылкой.")
    if dest_known.is_file():
        lookup = identity_lookup(host, port)
        already = run("ssh-keygen", "-F", lookup, "-f", str(dest_known),
                      check=False, capture=True)
        if already.returncode != 0:
            with dest_known.open("a", encoding="utf-8") as file:
                file.write("\n" + known)
    else:
        atomic_secret(dest_known, known)
    os.chown(dest_known, uid, gid)
    os.chmod(dest_known, 0o600)
    info("SSH-ключ и проверенный known_hosts сохранены с ограниченным доступом.")
    return {"name": name, "host": host, "port": port, "username": username,
            "key_file": runtime_root + "/id_ed25519",
            "known_hosts_file": runtime_root + "/known_hosts"}


def add_server_command(cfg: dict):
    return ["server", "add",
            "--name", cfg["name"], "--host", cfg["host"],
            "--port", str(cfg["port"]), "--username", cfg["username"],
            "--key-file", cfg["key_file"], "--known-hosts-file", cfg["known_hosts_file"]]


def docker(*args: str):
    return run("docker", "compose", *args, cwd=ROOT)


def docker_preflight():
    require_commands("docker", "openssl")
    run("docker", "info", capture=True)
    run("docker", "compose", "version", capture=True)
    if not (ROOT / "docker-compose.yml").is_file():
        raise InstallError("Не найден docker-compose.yml. Запустите мастер из репозитория.")


def systemd_preflight():
    require_commands("python3", "systemctl", "useradd", "openssl", "runuser")
    version = tuple(sys.version_info[:2])
    if version < (3, 12):
        raise InstallError("Для systemd требуется Python 3.12+. Для Docker достаточно стандартного Python.")
    with tempfile.TemporaryDirectory(prefix="osgate-venv-") as tmp:
        probe = Path(tmp) / "test"
        try:
            run("python3", "-m", "venv", str(probe), capture=True)
        except InstallError as exc:
            package = f"python3.{sys.version_info.minor}-venv"
            if not shutil.which("apt-get") or not yesno(
                    f"Не найден venv/ensurepip. Установить пакет {package} через apt?", False):
                raise InstallError(
                    f"Установите {package}: sudo apt-get install {package}") from exc
            # Installing OS packages is a distinct, opt-in side effect. Never
            # silently install Docker or change apt repositories.
            run("apt-get", "update")
            run("apt-get", "install", "-y", package)
            run("python3", "-m", "venv", str(probe), capture=True)
            info(f"Установлен {package}.")


def existing_docker_install() -> bool:
    return (ROOT / ".env").exists() or (ROOT / "data" / "osgate.db").exists()


def docker_install():
    require_root()
    section("Docker Compose · установка")
    docker_preflight()
    if existing_docker_install():
        raise InstallError("Найдена существующая установка. Используйте sudo ./install.sh --update --mode docker.")
    admin = user_value(ask("Логин администратора", "admin"))
    web_port = port_value(ask("Порт веб-панели на хосте", "5812"))
    socks_port = port_value(ask("Порт SOCKS5 на хосте", "1080"))
    if web_port == socks_port:
        raise InstallError("Порты веб-панели и SOCKS5 должны различаться.")
    socks_bind = select_socks_access()
    check_bind_port("127.0.0.1", web_port)
    check_bind_port(socks_bind, socks_port)
    data = ROOT / "data"
    ssh_dir = ROOT / "ssh"
    for directory in (data, ssh_dir):
        if directory.is_symlink():
            raise InstallError(f"Каталог-ссылка запрещён: {directory}")
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chown(directory, 10001, 10001)
        os.chmod(directory, 0o700)
    remote = ssh_setup(ssh_dir, 10001, 10001, "/ssh")
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    env = set_env_values(template, {
        "SESSION_SECRET": secrets.token_hex(32),
        "OSGATE_HOST_WEB_PORT": str(web_port),
        "OSGATE_HOST_SOCKS_PORT": str(socks_port),
        "OSGATE_HOST_SOCKS_BIND": socks_bind,
    })
    atomic_secret(ROOT / ".env", env)
    info("Создана конфигурация .env (0600); firewall не изменялся.")
    section("Сборка и создание администратора")
    docker("config", "--quiet")
    docker("build")
    print("Введите пароль администратора (минимум 12 символов); он не отображается.")
    docker("run", "--rm", "--entrypoint", "osgate", "osgate", "admin", "create", admin)
    if remote:
        docker("run", "--rm", "--entrypoint", "osgate", "osgate", *add_server_command(remote))
    docker("up", "-d")
    if not check_health(web_port):
        raise InstallError("Контейнер создан, но /healthz не ответил. Проверьте: docker compose logs --tail 100")
    info(f"OSGate запущен: http://127.0.0.1:{web_port}")
    info(f"SOCKS5: {socks_bind}:{socks_port} · Логин администратора: {admin}")
    print("Веб-панель с другого компьютера: используйте SSH-туннель, не открывайте порт в интернет.")
    print(f"  ssh -L {web_port}:127.0.0.1:{web_port} <user>@<OSGate-host>")
    if not remote:
        print("Добавьте SSH-сервер и SOCKS5-клиента через веб-панель.")


def copy_source(target: Path, replacing=False):
    if target.is_symlink():
        raise InstallError("Каталог установки является символической ссылкой.")
    if target.exists() and not replacing:
        raise InstallError("OSGate уже установлен в /opt/osgate. Используйте --update.")
    if not target.exists():
        shutil.copytree(ROOT, target, ignore=shutil.ignore_patterns(*EXCLUDED))
        return
    # Update code only: database, system configuration and SSH files live elsewhere.
    for item in ROOT.iterdir():
        if item.name in EXCLUDED:
            continue
        destination = target / item.name
        if item.is_symlink():
            raise InstallError("Символические ссылки в исходниках не поддерживаются.")
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(*EXCLUDED))
        elif item.is_file():
            shutil.copy2(item, destination)


def system_command(*argv: str):
    shell = (
        'set -a; . /etc/osgate/osgate.env; set +a; '
        'exec /opt/osgate/.venv/bin/osgate "$@"'
    )
    return run("runuser", "-u", "osgate", "--", "bash", "-c", shell,
               "osgate-cli", *argv)


def systemd_install():
    require_root()
    section("systemd · установка")
    systemd_preflight()
    if SYSTEM_ROOT.exists() or SYSTEM_ENV.exists():
        raise InstallError("Найдена существующая установка; используйте --update --mode systemd.")
    admin = user_value(ask("Логин администратора", "admin"))
    web_port = port_value(ask("Локальный порт веб-панели", "5812"))
    socks_port = port_value(ask("Локальный порт SOCKS5", "1080"))
    if web_port == socks_port:
        raise InstallError("Порты должны различаться.")
    socks_bind = select_socks_access()
    check_bind_port("127.0.0.1", web_port)
    check_bind_port(socks_bind, socks_port)
    if not yesno("Установить системную службу? Firewall не изменяется.", True):
        raise InstallError("Установка отменена.")
    SYSTEM_ROOT.parent.mkdir(parents=True, exist_ok=True)
    copy_source(SYSTEM_ROOT)
    run("bash", str(SYSTEM_ROOT / "deploy" / "install.sh"))
    env = SYSTEM_ENV.read_text(encoding="utf-8")
    atomic_secret(SYSTEM_ENV, set_env_values(env, {
        "WEB_PORT": str(web_port), "SOCKS_PORT": str(socks_port),
        "WEB_HOST": "127.0.0.1", "SOCKS_HOST": socks_bind,
    }), replace=True)
    shutil.chown(SYSTEM_ENV, user="root", group="osgate")
    os.chmod(SYSTEM_ENV, 0o640)
    account = pwd.getpwnam("osgate")
    remote = ssh_setup(SYSTEM_SSH, account.pw_uid, account.pw_gid,
                       "/etc/osgate/ssh")
    print("Введите пароль администратора (минимум 12 символов).")
    system_command("admin", "create", admin)
    if remote:
        system_command(*add_server_command(remote))
    run("systemctl", "enable", "--now", "osgate")
    if not check_health(web_port):
        raise InstallError("Служба создана, но /healthz не ответил. Проверьте: journalctl -u osgate -n 100")
    info(f"OSGate запущен: http://127.0.0.1:{web_port}")
    info(f"SOCKS5 слушает {socks_bind}:{socks_port}")
    info("Автозапуск через systemd включён. Для проверки: sudo systemctl status osgate")
    if not remote:
        print("Добавьте SSH-сервер и SOCKS5-клиента через веб-панель.")


def backup_database(source: Path, output_dir: Path):
    if not source.is_file():
        return
    if source.is_symlink():
        raise InstallError("Нельзя делать резервную копию SQLite из символической ссылки.")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_dir, 0o700)
    dest = output_dir / f"osgate-{time.strftime('%Y%m%d-%H%M%S')}.db"
    if dest.exists():
        raise InstallError(f"Резервная копия уже существует: {dest}")
    with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as original:
        with sqlite3.connect(dest) as output:
            original.backup(output)
    os.chmod(dest, 0o600)
    info(f"Резервная копия SQLite: {dest}")


def pull_source():
    """Fetch new files as the checkout owner, never as root in another user's tree."""
    if not (ROOT / ".git").is_dir():
        raise InstallError("Для обновления нужен Git-клон репозитория OSGate.")
    owner = pwd.getpwuid(ROOT.stat().st_uid).pw_name
    args = ["git", "-C", str(ROOT), "pull", "--ff-only"]
    if os.geteuid() == 0 and owner != "root":
        require_commands("runuser")
        args = ["runuser", "-u", owner, "--", *args]
    return run(*args)


def update(mode: str):
    require_root()
    section(f"Обновление · {mode}")
    if not yesno("Сохранить текущую конфигурацию и обновить код?", False):
        raise InstallError("Обновление отменено.")
    if mode == "docker":
        docker_preflight()
        if not (ROOT / ".env").exists():
            raise InstallError("Не найдена .env, сначала установите приложение.")
        backup_database(ROOT / "data" / "osgate.db", ROOT / "backups")
        pull_source()
        docker("up", "-d", "--build")
        info("Контейнер обновлён; .env, SSH-ключи и база не перезаписаны.")
    else:
        systemd_preflight()
        if not SYSTEM_ENV.exists() or not SYSTEM_ROOT.exists():
            raise InstallError("Служба ещё не установлена.")
        backup_database(Path("/var/lib/osgate/osgate.db"), ROOT / "backups")
        pull_source()
        copy_source(SYSTEM_ROOT, replacing=True)
        run("bash", str(SYSTEM_ROOT / "deploy" / "install.sh"))
        run("systemctl", "restart", "osgate")
        info("Служба обновлена; конфигурация и данные сохранены.")


def configure_access(mode: str):
    """Change only SOCKS bind address; keep all other values and data intact."""
    require_root()
    section(f"Изменение доступа SOCKS5 · {mode}")
    if mode == "docker":
        docker_preflight()
        path = ROOT / ".env"
        if not path.is_file() or path.is_symlink():
            raise InstallError("Не найден безопасный файл .env Docker.")
        current = path.read_text(encoding="utf-8")
        # Legacy configs published only on localhost: avoid guessing broad access.
        old_bind = re.search(r"(?m)^OSGATE_HOST_SOCKS_BIND=(.+)$", current)
        current_bind = old_bind.group(1) if old_bind else "127.0.0.1"
        new_bind = select_socks_access()
        if new_bind == current_bind:
            info("Доступ не изменился.")
            return
        if not yesno(f"Применить SOCKS5 {current_bind} → {new_bind}? "
                     "Docker-контейнер будет пересоздан.", False):
            raise InstallError("Изменение доступа отменено.")
        updated = set_env_values(current, {"OSGATE_HOST_SOCKS_BIND": new_bind})
        # Store a rollback snapshot before changing the environment.
        backup = ROOT / "backups"
        backup.mkdir(mode=0o700, exist_ok=True)
        os.chmod(backup, 0o700)
        old = backup / f"osgate-env-{time.time_ns()}.bak"
        atomic_secret(old, current)
        atomic_secret(path, updated, replace=True)
        try:
            docker("config", "--quiet")
            docker("up", "-d", "--no-build")
        except InstallError:
            atomic_secret(path, current, replace=True)
            # Best effort to return to the old port mapping.
            try:
                docker("up", "-d", "--no-build")
            except InstallError:
                pass
            raise
        info(f"SOCKS5: {new_bind} · Старая конфигурация: {old}")
    else:
        path = SYSTEM_ENV
        if not path.is_file() or path.is_symlink():
            raise InstallError("Не найдена безопасная конфигурация systemd.")
        current = path.read_text(encoding="utf-8")
        match = re.search(r"(?m)^SOCKS_HOST=(.+)$", current)
        old_bind = match.group(1) if match else "127.0.0.1"
        new_bind = select_socks_access()
        if new_bind == old_bind:
            info("Доступ не изменился.")
            return
        if not yesno(f"Применить SOCKS5 {old_bind} → {new_bind}? "
                     "Служба будет перезапущена.", False):
            raise InstallError("Изменение доступа отменено.")
        updated = set_env_values(current, {"SOCKS_HOST": new_bind})
        backup = ROOT / "backups"
        backup.mkdir(mode=0o700, exist_ok=True)
        os.chmod(backup, 0o700)
        old = backup / f"osgate-systemd-env-{time.time_ns()}.bak"
        atomic_secret(old, current)
        atomic_secret(path, updated, replace=True)
        shutil.chown(path, user="root", group="osgate")
        os.chmod(path, 0o640)
        try:
            run("systemctl", "restart", "osgate")
        except InstallError:
            atomic_secret(path, current, replace=True)
            shutil.chown(path, user="root", group="osgate")
            os.chmod(path, 0o640)
            try:
                run("systemctl", "restart", "osgate")
            except InstallError:
                pass
            raise
        info(f"SOCKS5: {new_bind} · Старая конфигурация: {old}")
    print("Firewall автоматически не изменялся; проверьте доступ с доверенного IP.")


def check(mode: str) -> bool:
    section(f"Диагностика · {mode}")
    if mode == "docker":
        docker_preflight()
        if not (ROOT / ".env").is_file():
            raise InstallError("Файл .env отсутствует; приложение ещё не настроено.")
        docker("config", "--quiet")
        docker("ps")
        env = (ROOT / ".env").read_text(encoding="utf-8")
        match = re.search(r"(?m)^OSGATE_HOST_WEB_PORT=(\d+)$", env)
        port = int(match.group(1)) if match else 5812
    else:
        run("systemctl", "is-active", "--quiet", "osgate")
        env = SYSTEM_ENV.read_text(encoding="utf-8")
        match = re.search(r"(?m)^WEB_PORT=(\d+)$", env)
        port = int(match.group(1)) if match else 5812
    health = check_health(port, attempts=2, pause=0.2)
    info(f"HTTP healthcheck: {'OK' if health else 'не отвечает'} (127.0.0.1:{port})")
    return health


def choose_mode() -> str:
    print("1 — Docker Compose (рекомендуется)")
    print("2 — systemd без Docker")
    option = ask("Выберите способ установки", "1")
    if option not in {"1", "2"}:
        raise InstallError("Выберите 1 или 2.")
    return "docker" if option == "1" else "systemd"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="OSGate — мастер установки Docker / systemd")
    parser.add_argument("--mode", choices=("docker", "systemd"),
                        help="Выбрать способ установки без меню")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Диагностика установки")
    group.add_argument("--update", action="store_true", help="Обновление с сохранением данных")
    group.add_argument("--access", action="store_true",
                       help="Изменить доступность SOCKS5 без переустановки")
    args = parser.parse_args(argv)
    print("\n  OSGate · мастер установки\n  SOCKS5 → SSH → Internet\n")
    try:
        if not sys.stdin.isatty() and not args.check:
            raise InstallError("Нужен интерактивный терминал. Для диагностики используйте --check.")
        mode = args.mode or choose_mode()
        if args.check:
            return 0 if check(mode) else 1
        if args.update:
            update(mode)
        elif args.access:
            configure_access(mode)
        elif mode == "docker":
            docker_install()
        else:
            systemd_install()
        print("\n✓ Готово. Пароли и SSH-ключи не выводились в консоль.\n")
        return 0
    except (InstallError, KeyboardInterrupt, EOFError) as exc:
        print(f"\n✗ {exc or 'Установка прервана'}", file=sys.stderr)
        print("Существующие данные не удалялись. Для диагностики: ./install.sh --check --mode docker",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
