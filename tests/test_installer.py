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
    assert "${OSGATE_HOST_SOCKS_BIND:-127.0.0.1}:${OSGATE_HOST_SOCKS_PORT:-1080}:1080" in content
    assert "restart: unless-stopped" in content



def test_mocked_docker_wizard_creates_env_without_remote_changes(tmp_path, monkeypatch):
    import shutil
    shutil.copy2(ROOT / ".env.example", tmp_path / ".env.example")
    shutil.copy2(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "docker_preflight", lambda: None)
    monkeypatch.setattr(wizard, "check_bind_port", lambda *args: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "127.0.0.1")
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
    assert "OSGATE_HOST_SOCKS_BIND=127.0.0.1" in env
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



def test_pull_source_requires_checkout_and_uses_checkout_owner(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard.os, "geteuid", lambda: 0)
    monkeypatch.setattr(wizard.pwd, "getpwuid", lambda uid: type("Owner", (), {"pw_name": "developer"})())
    monkeypatch.setattr(wizard, "require_commands", lambda *args: None)
    called = []
    monkeypatch.setattr(wizard, "run", lambda *args: called.append(args))
    wizard.pull_source()
    assert called == [("runuser", "-u", "developer", "--", "git", "-C",
                       str(tmp_path), "pull", "--ff-only")]



def test_socks_ipv4_interface_validation(monkeypatch):
    monkeypatch.setattr(wizard, "interface_addresses",
                        lambda: {"127.0.0.1", "0.0.0.0", "192.168.10.24"})
    assert wizard.validate_socks_bind("192.168.10.24") == "192.168.10.24"
    assert wizard.validate_socks_bind("0.0.0.0") == "0.0.0.0"
    for value in ("300.1.1.1", "hostname", "10.1.2.3"):
        with pytest.raises(wizard.InstallError):
            wizard.validate_socks_bind(value)
    with pytest.raises(wizard.InstallError):
        wizard.bind_address("::")


def test_select_access_modes_and_explicit_confirmation(monkeypatch):
    monkeypatch.setattr(wizard, "interface_addresses",
                        lambda: {"127.0.0.1", "0.0.0.0", "10.20.30.40"})
    monkeypatch.setattr(wizard, "ask", lambda *args: "1")
    assert wizard.select_socks_access() == "127.0.0.1"
    monkeypatch.setattr(wizard, "ask", lambda *args: "2")
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: False)
    with pytest.raises(wizard.InstallError):
        wizard.select_socks_access()
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: True)
    assert wizard.select_socks_access() == "0.0.0.0"
    answers = iter(["3", "10.20.30.40"])
    monkeypatch.setattr(wizard, "ask", lambda *args: next(answers))
    assert wizard.select_socks_access() == "10.20.30.40"


def test_docker_install_public_option_never_exposes_admin(tmp_path, monkeypatch):
    import shutil
    shutil.copy2(ROOT / ".env.example", tmp_path / ".env.example")
    shutil.copy2(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "docker_preflight", lambda: None)
    monkeypatch.setattr(wizard, "check_bind_port", lambda *args: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "0.0.0.0")
    monkeypatch.setattr(wizard.os, "chown", lambda *args, **kwargs: None)
    answers = iter(["admin", "15812", "11080"])
    monkeypatch.setattr(wizard, "ask", lambda *args, **kwargs: next(answers))
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: False)
    calls = []
    monkeypatch.setattr(wizard, "docker", lambda *args: calls.append(args))
    monkeypatch.setattr(wizard, "check_health", lambda port: port == 15812)
    wizard.docker_install()
    env = (tmp_path / ".env").read_text()
    assert "OSGATE_HOST_SOCKS_BIND=0.0.0.0" in env
    assert "WEB_ALLOWED_CIDRS=127.0.0.1/32,::1/128" in env
    assert "SESSION_SECRET=REPLACE" not in env


def test_docker_access_change_keeps_env_and_restarts(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "SESSION_SECRET=old-value\nOSGATE_HOST_SOCKS_BIND=127.0.0.1\n"
        "OSGATE_HOST_WEB_PORT=5812\n")
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "docker_preflight", lambda: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "0.0.0.0")
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: True)
    calls = []
    monkeypatch.setattr(wizard, "docker", lambda *args: calls.append(args))
    wizard.configure_access("docker")
    new_env = (tmp_path / ".env").read_text()
    assert "SESSION_SECRET=old-value" in new_env
    assert "OSGATE_HOST_WEB_PORT=5812" in new_env
    assert "OSGATE_HOST_SOCKS_BIND=0.0.0.0" in new_env
    assert ("up", "-d", "--no-build") in calls
    assert len(list((tmp_path / "backups").glob("osgate-env-*"))) == 1


def test_docker_access_change_rolls_back_if_recreate_fails(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text(
        "OSGATE_HOST_SOCKS_BIND=127.0.0.1\nSESSION_SECRET=unchanged\n")
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "docker_preflight", lambda: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "0.0.0.0")
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: True)
    attempts = []
    def fake_docker(*args):
        attempts.append(args)
        if args == ("up", "-d", "--no-build") and attempts.count(args) == 1:
            raise wizard.InstallError("broken Docker")
    monkeypatch.setattr(wizard, "docker", fake_docker)
    with pytest.raises(wizard.InstallError):
        wizard.configure_access("docker")
    assert "OSGATE_HOST_SOCKS_BIND=127.0.0.1" in (tmp_path / ".env").read_text()
    assert attempts.count(("up", "-d", "--no-build")) == 2



def test_mocked_systemd_install_honors_external_socks_binding(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(wizard, "ROOT", tmp_path / "repo")
    monkeypatch.setattr(wizard, "SYSTEM_ROOT", tmp_path / "opt" / "osgate")
    monkeypatch.setattr(wizard, "SYSTEM_ENV", tmp_path / "etc" / "osgate.env")
    monkeypatch.setattr(wizard, "SYSTEM_SSH", tmp_path / "etc" / "ssh")
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "systemd_preflight", lambda: None)
    monkeypatch.setattr(wizard, "check_bind_port", lambda *args: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "0.0.0.0")
    monkeypatch.setattr(wizard, "copy_source", lambda p: p.mkdir(parents=True))
    monkeypatch.setattr(wizard.shutil, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(wizard.os, "chmod", lambda *args: None)
    monkeypatch.setattr(wizard.pwd, "getpwnam",
                        lambda u: SimpleNamespace(pw_uid=11001, pw_gid=11001))
    monkeypatch.setattr(wizard, "ssh_setup", lambda *args: None)
    monkeypatch.setattr(wizard, "system_command", lambda *args: None)
    monkeypatch.setattr(wizard, "check_health", lambda port: port == 15812)
    answers = iter(["admin", "15812", "11080"])
    monkeypatch.setattr(wizard, "ask", lambda *args: next(answers))
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: True)
    calls = []
    def fake_run(*args, **kwargs):
        calls.append(args)
        if args[:1] == ("bash",):
            wizard.SYSTEM_ENV.parent.mkdir(parents=True, exist_ok=True)
            wizard.SYSTEM_ENV.write_text(
                "SESSION_SECRET=kept\nWEB_HOST=127.0.0.1\n"
                "SOCKS_HOST=127.0.0.1\n"
            )
    monkeypatch.setattr(wizard, "run", fake_run)
    wizard.systemd_install()
    env = wizard.SYSTEM_ENV.read_text()
    assert "SOCKS_HOST=0.0.0.0" in env
    assert "WEB_HOST=127.0.0.1" in env
    assert "SESSION_SECRET=kept" in env
    assert ("systemctl", "enable", "--now", "osgate") in calls


def test_systemd_access_change_keeps_config_and_restarts(tmp_path, monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(wizard, "ROOT", tmp_path)
    conf = tmp_path / "systemd.env"
    conf.write_text("SESSION_SECRET=old-secret\nSOCKS_HOST=127.0.0.1\nWEB_HOST=127.0.0.1\n")
    monkeypatch.setattr(wizard, "SYSTEM_ENV", conf)
    monkeypatch.setattr(wizard, "require_root", lambda: None)
    monkeypatch.setattr(wizard, "select_socks_access", lambda: "192.168.1.10")
    monkeypatch.setattr(wizard, "yesno", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard.shutil, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(wizard.os, "chmod", lambda *args: None)
    commands = []
    monkeypatch.setattr(wizard, "run", lambda *args: commands.append(args))
    wizard.configure_access("systemd")
    assert "SOCKS_HOST=192.168.1.10" in conf.read_text()
    assert "WEB_HOST=127.0.0.1" in conf.read_text()
    assert "SESSION_SECRET=old-secret" in conf.read_text()
    assert commands == [("systemctl", "restart", "osgate")]
    assert list((tmp_path / "backups").glob("osgate-systemd-env-*"))
