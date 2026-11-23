import pytest
from osgate.config import Settings
from osgate.database import Database, Client, SSHServer, Admin, hasher


@pytest.fixture
def setup(tmp_path):
    cfg = Settings(session_secret='a' * 64,
                   database_url='sqlite:///' + str(tmp_path / 'osgate.db'),
                   ssh_directory=tmp_path,
                   socks_host='127.0.0.1', socks_port=1080,
                   health_check_interval=0.5, health_check_timeout=1,
                   health_success_threshold=1, health_failure_threshold=1,
                   ssh_reconnect_initial_delay=0.2, ssh_reconnect_max_delay=1)
    db = Database(cfg.database_url)
    db.initialize()
    with db.session() as s:
        s.add(Admin(username='admin', password_hash=hasher.hash('secret-admin-password')))
        s.add(Client(name='Browser', username='browser', password_hash=hasher.hash('client-password-123'),
                     max_connections=3))
    return cfg, db
