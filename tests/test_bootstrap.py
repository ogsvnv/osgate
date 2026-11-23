"""End-to-end bootstrap smoke checks without sudo, installation or remote SSH."""
from pathlib import Path
import os
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bootstrap.sh"


def test_bootstrap_shellcheck_and_help():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-S", "warning", str(SCRIPT)], check=True)
    result = subprocess.run(["bash", str(SCRIPT), "--help"],
                            capture_output=True, text=True, check=True)
    assert "curl -fsSL" in result.stdout
    assert "--mode docker|systemd" in result.stdout
    assert "--update" in result.stdout


@pytest.mark.parametrize("args", [
    ["--mode", "invalid"], ["--dir"], ["--mode"],
    ["--check", "--update"], ["--unknown"],
])
def test_bootstrap_rejects_bad_arguments(args):
    result = subprocess.run(["bash", str(SCRIPT), *args],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert "Ошибка:" in result.stderr


def test_bootstrap_rejects_non_tty_without_installing(tmp_path):
    result = subprocess.run(["bash", str(SCRIPT), "--dir", str(tmp_path / "osgate")],
                            capture_output=True, text=True, input="")
    assert result.returncode != 0
    assert not (tmp_path / "osgate").exists()


def test_bootstrap_pipe_with_tty_and_fake_git_sudo(tmp_path):
    """Simulates: cat bootstrap.sh | bash -s -- --mode docker."""
    if not shutil.which("script"):
        pytest.skip("util-linux script unavailable")
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    clone = tmp_path / "osgate"

    git = fakebin / "git"
    git.write_text("""#!/usr/bin/env bash
set -eu
if [[ "$1" != clone ]]; then exit 89; fi
last="${!#}"
mkdir -p "$last/deploy"
printf '#!/usr/bin/env bash\\nprintf "installer called\\\\n"\\n' > "$last/install.sh"
printf '# fake wizard\\n' > "$last/deploy/wizard.py"
""")
    git.chmod(0o755)

    sudo = fakebin / "sudo"
    sudo.write_text("""#!/usr/bin/env bash
set -eu
[[ -t 0 ]] || { echo "NO_TTY" >&2; exit 90; }
printf 'sudo-called:%s\\n' "$*" > "$BOOTSTRAP_TEST_LOG"
exit 0
""")
    sudo.chmod(0o755)
    env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ["PATH"],
               BOOTSTRAP_TEST_LOG=str(tmp_path / "sudo.log"))
    command = ("cat " + str(SCRIPT) + " | bash -s -- --mode docker --dir " + str(clone))
    completed = subprocess.run(
        ["script", "-q", "-e", "-c", command, "/dev/null"],
        text=True, capture_output=True, env=env, timeout=20,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (tmp_path / "sudo.log").read_text().strip() == (
        "sudo-called:bash ./install.sh --mode docker"
    )
    assert (clone / "install.sh").exists()


def test_bootstrap_rejects_existing_non_git_directory(tmp_path):
    if not shutil.which("script"):
        pytest.skip("util-linux script unavailable")
    target = tmp_path / "occupied"
    target.mkdir()
    process = subprocess.run(
        ["script", "-q", "-e", "-c",
         "bash " + str(SCRIPT) + " --dir " + str(target), "/dev/null"],
        capture_output=True, text=True, timeout=20,
    )
    assert process.returncode != 0
    assert "Каталог занят другой установкой" in process.stdout
