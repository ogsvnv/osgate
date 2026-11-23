"""SSH key onboarding: security, remote install, and authenticated web flows."""
import asyncio
import os
from pathlib import Path
import re
import subprocess

import asyncssh
import httpx
import pytest

from osgate.app import create_app
from osgate.database import SSHServer
from osgate.ssh_onboarding import (
    EnrollmentError, credential_path, derive_public_key, enroll_public_key,
    installation_command,
)
from .test_socks5 import free_port


def test_derive_public_key_without_exposing_private_material(tmp_path):
    key = tmp_path / "key"
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    public = derive_public_key(key)
    assert public.startswith("ssh-ed25519 ")
    assert len(public.split()) == 2
    assert "PRIVATE" not in public
    assert not any(ch in public for ch in ("\n", "\r", "'"))


def test_authorized_keys_append_is_idempotent_and_preserves_other_keys(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    sshdir = home / ".ssh"
    sshdir.mkdir()
    existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexisting existing-comment\n"
    destination = sshdir / "authorized_keys"
    destination.write_text(existing)
    new = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewkey"
    command = installation_command(new)
    for _ in range(2):
        subprocess.run(["sh", "-c", command], env={**os.environ, "HOME": str(home)}, check=True)
    result = destination.read_text()
    assert result.count(new) == 1
    assert existing in result
    assert destination.stat().st_mode & 0o777 == 0o600
    assert sshdir.stat().st_mode & 0o777 == 0o700


def test_key_paths_cannot_escape_ssh_dir(tmp_path):
    sshdir = tmp_path / "ssh"
    sshdir.mkdir()
    external = tmp_path / "outside"
    external.write_text("secret")
    (sshdir / "escape").symlink_to(external)
    with pytest.raises(EnrollmentError):
        credential_path(str(external), sshdir)
    with pytest.raises(EnrollmentError):
        credential_path(str(sshdir / "escape"), sshdir)


@pytest.mark.asyncio
async def test_enroll_passes_transient_password_and_verified_known_hosts(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    known = tmp_path / "known_hosts"
    known.write_text("ssh.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIknown\n")
    class Settings:
        ssh_directory = tmp_path
        ssh_connect_timeout = 2
    record = dict(host="ssh.example", port=2222, username="sshuser",
                  key_file=str(key), known_hosts_file=str(known))
    captured = {}
    class FakeConn:
        async def run(self, command, check=False):
            captured["command"] = command
            return type("Result", (), {"exit_status": 0})()
        def close(self):
            captured["closed"] = True
        async def wait_closed(self):
            pass
    async def fake_connect(host, **kwargs):
        captured["host"] = host
        captured["kwargs"] = kwargs
        return FakeConn()
    monkeypatch.setattr("osgate.ssh_onboarding.asyncssh.connect", fake_connect)
    await enroll_public_key(record, Settings(), "transient-super-secret")
    assert captured["kwargs"]["known_hosts"] == str(known)
    assert captured["kwargs"]["password"] == "transient-super-secret"
    assert captured["kwargs"]["client_keys"] == []
    assert captured["kwargs"]["agent_path"] is None
    assert "transient-super-secret" not in captured["command"]
    assert "ssh-ed25519" in captured["command"]
    assert captured["closed"] is True


@pytest.mark.asyncio
async def test_enrollment_rejects_ssh_permission_denied(tmp_path, monkeypatch):
    key = tmp_path / "key"
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    known = tmp_path / "known_hosts"
    known.write_text("entry")
    class Settings:
        ssh_directory = tmp_path
        ssh_connect_timeout = 2
    async def fail(*args, **kwargs):
        raise asyncssh.PermissionDenied("secret password should not be repeated")
    monkeypatch.setattr("osgate.ssh_onboarding.asyncssh.connect", fail)
    with pytest.raises(EnrollmentError, match="отклонил пароль") as exc:
        await enroll_public_key(dict(host="ssh.example", port=22,
               username="tester", key_file=str(key), known_hosts_file=str(known)),
               Settings(), "transient-super-secret")
    assert "transient-super-secret" not in str(exc.value)
    assert "secret password should not be repeated" not in str(exc.value)


@pytest.mark.asyncio
async def test_web_onboarding_requires_admin_csrf_and_confirmation(setup, monkeypatch):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    with db.session() as s:
        s.add(SSHServer(name="gamma", host="ssh.example", port=22, username="sshuser",
                        key_file="/ssh/key", known_hosts_file="/ssh/known_hosts"))
    calls = []
    async def fake_enroll(record, settings, password):
        calls.append((record["id"] if "id" in record else record["host"], password))
    async def fake_probe(record, settings):
        calls.append(("probe", record["host"]))
    monkeypatch.setattr("osgate.web_v1.enroll_public_key", fake_enroll)
    monkeypatch.setattr("osgate.web_v1.probe_ssh", fake_probe)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=app, client=("127.0.0.1", 49144)), base_url="http://127.0.0.1") as h:
            assert (await h.get("/servers/1/onboard")).status_code == 401
            login = await h.get("/login")
            token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            await h.post("/login", data={"username": "admin",
                            "password": "secret-admin-password", "csrf": token})
            form = await h.get("/servers/1/onboard")
            assert form.status_code == 200
            assert 'name="ssh_password"' in form.text
            assert "sshuser@ssh.example" in form.text
            token = re.search(r'name="csrf" value="([^"]+)"', form.text).group(1)
            assert (await h.post("/servers/1/onboard", data={
                "csrf": "bad", "ssh_password": "do-not-persist",
                "confirm_key_install": "yes"})).status_code == 403
            assert (await h.post("/servers/1/onboard", data={
                "csrf": token, "ssh_password": "do-not-persist"})).status_code == 400
            assert calls == []
            result = await h.post("/servers/1/onboard", data={
                "csrf": token, "ssh_password": "do-not-persist",
                "confirm_key_install": "yes"})
            assert result.status_code == 200
            assert "SSH успешно настроен" in result.text
            assert calls == [("ssh.example", "do-not-persist"), ("probe", "ssh.example")]
            assert "do-not-persist" not in result.text
            with db.session() as s:
                item=s.get(SSHServer, 1)
                assert item.host == "ssh.example"
                assert not hasattr(item, "ssh_password")


@pytest.mark.asyncio
async def test_enrollment_throttled_and_password_not_exposed(setup, monkeypatch):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    with db.session() as s:
        s.add(SSHServer(name="gamma", host="ssh.example", port=22, username="sshuser",
                        key_file="/ssh/key", known_hosts_file="/ssh/known_hosts"))
    async def deny(*args):
        raise EnrollmentError("Сервер отклонил пароль SSH.")
    monkeypatch.setattr("osgate.web_v1.enroll_public_key", deny)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=app, client=("127.0.0.1", 49145)), base_url="http://127.0.0.1") as h:
            login = await h.get("/login")
            token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            await h.post("/login", data={"username": "admin",
                            "password": "secret-admin-password", "csrf": token})
            form=await h.get("/servers/1/onboard")
            token = re.search(r'name="csrf" value="([^"]+)"', form.text).group(1)
            for _ in range(5):
                r=await h.post("/servers/1/onboard", data={
                    "csrf": token, "ssh_password": "NEVER_LOG_THIS",
                    "confirm_key_install": "yes"})
                assert r.status_code == 200
                assert "NEVER_LOG_THIS" not in r.text
            limit=await h.post("/servers/1/onboard", data={
                "csrf": token, "ssh_password": "NEVER_LOG_THIS",
                "confirm_key_install": "yes"})
            assert limit.status_code == 429



@pytest.mark.asyncio
async def test_new_server_can_enroll_key_before_initial_ssh_probe(setup, monkeypatch):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    calls = []
    async def fake_enroll(record, settings, password):
        calls.append(("enroll", record["host"], password))
    class FakeConn:
        async def open_connection(self, host, port):
            calls.append(("forward", host, port))
            return None, type("Writer", (), {"close": lambda self: None})()
        def close(self):
            pass
        async def wait_closed(self):
            pass
    async def fake_connect(record, settings):
        calls.append(("ssh", record["host"]))
        return FakeConn()
    monkeypatch.setattr("osgate.ssh_onboarding.enroll_public_key", fake_enroll)
    monkeypatch.setattr("osgate.web.connect_ssh", fake_connect)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(
                app=app, client=("127.0.0.1", 49146)),
                base_url="http://127.0.0.1") as h:
            login = await h.get("/login")
            token = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            await h.post("/login", data={"username": "admin",
                         "password": "secret-admin-password", "csrf": token})
            page = await h.get("/servers")
            assert "Настроить SSH-доступ через пароль при добавлении" in page.text
            token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
            payload = dict(csrf=token, name="new-host", host="ssh.example",
                           port="2222", username="sshuser", priority="10", weight="1",
                           key_file="/ssh/key", known_hosts_file="/ssh/known_hosts",
                           install_key="yes", ssh_password="one-time-secret")
            result=await h.post("/servers/new", data=payload)
            assert result.status_code == 303
            assert calls[0] == ("enroll", "ssh.example", "one-time-secret")
            assert calls[1] == ("ssh", "ssh.example")
            assert calls[2][0] == "forward"
            assert "one-time-secret" not in str(db.servers())
            assert db.servers()[0]["name"] == "new-host"


def test_authorized_keys_without_final_newline_remains_parseable(tmp_path):
    home = tmp_path / "home"
    sshdir = home / ".ssh"
    sshdir.mkdir(parents=True)
    f = sshdir / "authorized_keys"
    f.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexisting")
    new = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAInewkey"
    subprocess.run(["sh", "-c", installation_command(new)],
                   env={**os.environ, "HOME": str(home)}, check=True)
    lines = [line for line in f.read_text().splitlines() if line]
    assert lines == ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexisting", new]
