"""Deployment contract checks which run without Docker daemon or root access."""
import configparser
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_systemd_unit_is_unprivileged_and_persistent():
    conf = configparser.ConfigParser(interpolation=None)
    conf.read(ROOT / "deploy/systemd/osgate.service")
    service = conf["Service"]
    assert service["User"] == "osgate"
    assert service["Group"] == "osgate"
    assert service["Restart"] == "on-failure"
    assert service["NoNewPrivileges"] == "true"
    assert service["ProtectSystem"] == "strict"
    assert "/var/lib/osgate" in service["ReadWritePaths"]
    assert service["EnvironmentFile"] == "/etc/osgate/osgate.env"


def test_compose_bridge_ip_and_loopback_publishing():
    content = (ROOT / "docker-compose.yml").read_text()
    assert '"127.0.0.1:${OSGATE_HOST_WEB_PORT:-5812}:5812"' in content
    assert '"127.0.0.1:${OSGATE_HOST_SOCKS_PORT:-1080}:1080"' in content
    assert "DOCKER_WEB_ALLOWED_CIDRS" in content
    assert "172.16.0.0/12" in content
    assert "no-new-privileges:true" in content
    assert "cap_drop:" in content


def test_systemd_installer_syntax_and_venv_preflight():
    installer = ROOT / "deploy/install.sh"
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    subprocess.run(["bash", "-n", str(installer)], check=True)
    script = installer.read_text()
    assert "python3 -m venv" in script
    assert "venv_probe=" in script
    assert "ensurepip missing" in script
    assert "systemctl daemon-reload" in script
    assert "Firewall ports were not modified." in script
