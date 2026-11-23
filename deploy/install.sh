#!/usr/bin/env bash
# Run only after copying this repository to /opt/osgate; never changes firewall rules automatically.
set -euo pipefail
if [[ $EUID -ne 0 ]]; then echo 'Run as root with sudo' >&2; exit 1; fi
if [[ ! -f /opt/osgate/pyproject.toml ]]; then echo 'Copy the repository to /opt/osgate first' >&2; exit 1; fi
id osgate &>/dev/null || useradd --system --home-dir /var/lib/osgate --shell /usr/sbin/nologin osgate
install -d -o osgate -g osgate -m 0700 /var/lib/osgate
install -d -o root -g osgate -m 0750 /etc/osgate /etc/osgate/ssh
python3 -m venv /opt/osgate/.venv
/opt/osgate/.venv/bin/python -m pip install --no-cache-dir /opt/osgate
if [[ ! -f /etc/osgate/osgate.env ]]; then
  install -m 0640 -o root -g osgate /opt/osgate/.env.example /etc/osgate/osgate.env
  sed -i 's|DATABASE_URL=sqlite:////data/osgate.db|DATABASE_URL=sqlite:////var/lib/osgate/osgate.db|' /etc/osgate/osgate.env
  sed -i 's|SSH_DIRECTORY=/ssh|SSH_DIRECTORY=/etc/osgate/ssh|' /etc/osgate/osgate.env
  sed -i 's|WEB_HOST=0.0.0.0|WEB_HOST=127.0.0.1|' /etc/osgate/osgate.env
  sed -i 's|SOCKS_HOST=0.0.0.0|SOCKS_HOST=127.0.0.1|' /etc/osgate/osgate.env
  secret=$(openssl rand -hex 32)
  sed -i "s|SESSION_SECRET=.*|SESSION_SECRET=$secret|" /etc/osgate/osgate.env
fi
install -m 0644 /opt/osgate/deploy/systemd/osgate.service /etc/systemd/system/osgate.service
systemctl daemon-reload
printf '%s\n' 'Installed. Create admin with:' '  cd /opt/osgate && sudo -u osgate env $(cat /etc/osgate/osgate.env | grep -v "^#" | xargs) /opt/osgate/.venv/bin/osgate admin create admin' 'Then: systemctl enable --now osgate' 'Firewall ports were not modified.'
