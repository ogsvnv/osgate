"""No-root regression tests for the guided installation wizard."""
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("osgate_installer", ROOT / "deploy" / "wizard.py")
wizard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wizard)


def test_port_and_user_validation():
    assert wizard.port_value("5812") == 5812
    assert wizard.user_value("operator_1") == "operator_1"
    for value in ("0", "65536", "abcd", "-1"):
        with pytest.raises(wizard.InstallError):
            wizard.port_value(value)
    for value in ("root;rm", "x y", "-a", "", "test\nabc"):
        with pytest.raises(wizard.InstallError):
            wizard.user_value(value)


def test_hostname_validation():
    assert wizard.host_value("park.example.org") == "park.example.org"
    assert wizard.host_value("80.234.95.156") == "80.234.95.156"
    for bad in ("", "a b", "-x", "x;whoami", "x\nID", "../etc/passwd"):
        with pytest.raises(wizard.InstallError):
            wizard.host_value(bad)


def test_env_preserves_existing_data_and_escapes_values():
    existing = "SESSION_SECRET=existing\nWEB_PORT=5812\nUNRELATED=yes\n"
    output = wizard.set_env_values(existing, {"WEB_PORT": "15600", "NEW_OPTION": "x"})
    assert "SESSION_SECRET=existing" in output
    assert "WEB_PORT=15600" in output
    assert "UNRELATED=yes" in output
    assert output.count("WEB_PORT=") == 1
    with pytest.raises(wizard.InstallError):
        wizard.set_env_values(existing, {"WEB_PORT": "1\nEVIL=2"})


def test_atomic_secret_never_overwrites_by_default(tmp_path):
    path = tmp_path / "config"
    wizard.atomic_secret(path, "my-private-secret")
    assert path.read_text() == "my-private-secret"
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(wizard.InstallError):
        wizard.atomic_secret(path, "different")
    assert path.read_text() == "my-private-secret"


def test_atomic_secret_requires_explicit_replace(tmp_path):
    path = tmp_path / "settings"
    wizard.atomic_secret(path, "first")
    wizard.atomic_secret(path, "second", replace=True)
    assert path.read_text() == "second"


def test_sqlite_online_backup_does_not_modify_source(tmp_path):
    source = tmp_path / "db.sqlite"
    with sqlite3.connect(source) as db:
        db.execute("CREATE TABLE sample (value TEXT)")
        db.execute("INSERT INTO sample VALUES ('original')")
    backups = tmp_path / "backups"
    wizard.backup_database(source, backups)
    files = list(backups.glob("*.db"))
    assert len(files) == 1
    with sqlite3.connect(files[0]) as db:
        assert db.execute("SELECT value FROM sample").fetchone()[0] == "original"
    with sqlite3.connect(source) as db:
        assert db.execute("SELECT count(*) FROM sample").fetchone()[0] == 1


def test_entry_script_syntax_and_help():
    subprocess.run(["bash", "-n", str(ROOT / "install.sh")], check=True)
    result = subprocess.run([sys.executable, str(ROOT / "deploy" / "wizard.py"), "--help"],
                            text=True, capture_output=True, check=True)
    assert "--mode" in result.stdout
    assert "--update" in result.stdout
    assert "--check" in result.stdout


def test_refuse_noninteractive_install():
    process = subprocess.run(
        [sys.executable, str(ROOT / "deploy" / "wizard.py"), "--mode", "docker"],
        input="", capture_output=True, text=True,
    )
    assert process.returncode != 0
    assert "интерактивный терминал" in process.stderr


def test_compose_ports_are_localhost_only_and_configurable():
    content = (ROOT / "docker-compose.yml").read_text()
    assert "127.0.0.1:${OSGATE_HOST_WEB_PORT:-5812}:5812" in content
    assert "127.0.0.1:${OSGATE_HOST_SOCKS_PORT:-1080}:1080" in content
    assert "restart: unless-stopped" in content



def test_mocked_docker_wizard_creates_env_without_remote_changes(tmp_path, monkeypatch):
    import shutil
    shutil.copy2(ROOT / ".env.example", tmp_path / ".env.example")
    shutil.copy2(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "docker_preflight", lambda: None)
    monkeypatch.setattr(wizard, "unused_local_port", lambda port: None)
    monkeypatch.setattr(wizard.os, "chown", lambda *args, **kwargs: None)
    answers = iter(["admin", "15812", "11080"])
    monkeypatch.setattr(wizard, "ask", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr(wizard, "yesno", lambda label, default=False: True if
                        label.startswith("Порты") else False)
    calls = []
    monkeypatch.setattr(wizard, "docker", lambda *args: calls.append(args))
    monkeypatch.setattr(wizard, "check_health", lambda port: port == 15812)
    wizard.docker_install()
    env = (tmp_path / ".env").read_text()
    assert "OSGATE_HOST_WEB_PORT=15812" in env
    assert "OSGATE_HOST_SOCKS_PORT=11080" in env
    assert "SESSION_SECRET=REPLACE_WITH" not in env
    assert (tmp_path / ".env").stat().st_mode & 0o777 == 0o600
    assert ("build",) in calls
    assert ("run", "--rm", "--entrypoint", "osgate", "osgate",
            "admin", "create", "admin") in calls
    assert ("up", "-d") in calls

    # Attempting to install again must not alter credentials.
    saved = (tmp_path / ".env").read_text()
    with pytest.raises(wizard.InstallError):
        wizard.docker_install()
    assert (tmp_path / ".env").read_text() == saved


def test_known_hosts_requires_positive_manual_verification(monkeypatch):
    monkeypatch.setattr(wizard, "run", lambda *args, **kwargs: type("Cmd", (), {
        "stdout": "park.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI",
        "returncode": 0})())
    monkeypatch.setattr(wizard, "require_commands", lambda *args: None)
    monkeypatch.setattr(wizard, "ask", lambda *args, **kwargs: "НЕТ")
    with pytest.raises(wizard.InstallError, match="не подтверждён"):
        wizard.fetch_host_keys("park.example", 22)
