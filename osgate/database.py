"""SQLite models and small session-scoped repository methods."""
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from argon2 import PasswordHasher
from sqlalchemy import (create_engine, event, String, Integer, Boolean, Float, DateTime,
                        ForeignKey, BigInteger, select, func)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

hasher = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


class Admin(Base):
    __tablename__ = 'admin_users'
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))


class Client(Base):
    __tablename__ = 'socks_clients'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(String(300))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    max_connections: Mapped[int] = mapped_column(Integer, default=100)
    pinned_server_id: Mapped[int | None] = mapped_column(ForeignKey('ssh_servers.id'), nullable=True)
    allow_fallback: Mapped[bool] = mapped_column(Boolean, default=False)
    total_connections: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_uploaded: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_downloaded: Mapped[int] = mapped_column(BigInteger, default=0)
    last_active: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SSHServer(Base):
    __tablename__ = 'ssh_servers'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(120))
    key_file: Mapped[str] = mapped_column(String(255))
    known_hosts_file: Mapped[str] = mapped_column(String(255))
    priority: Mapped[int] = mapped_column(Integer, default=100)
    weight: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Routing(Base):
    __tablename__ = 'routing_settings'
    id: Mapped[int] = mapped_column(primary_key=True)
    mode: Mapped[str] = mapped_column(String(40), default='failover')
    manual_server_id: Mapped[int | None] = mapped_column(Integer)
    auto_failback: Mapped[bool] = mapped_column(Boolean, default=True)


class Event(Base):
    __tablename__ = 'events'
    id: Mapped[int] = mapped_column(primary_key=True)
    when: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    category: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(String(500))


class Audit(Base):
    __tablename__ = 'audit_logs'
    id: Mapped[int] = mapped_column(primary_key=True)
    when: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[str] = mapped_column(String(300))


class Database:
    def __init__(self, url: str):
        if not url.startswith('sqlite:///'):
            raise ValueError('Unsupported database')
        path = url.removeprefix('sqlite:///')
        if path != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(url, connect_args={'check_same_thread': False, 'timeout': 15})
        @event.listens_for(self.engine, 'connect')
        def configure_sqlite(dbapi_connection, _):
            cursor = dbapi_connection.cursor()
            cursor.execute('PRAGMA foreign_keys=ON')
            cursor.execute('PRAGMA busy_timeout=15000')
            cursor.execute('PRAGMA journal_mode=WAL')
            cursor.close()
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def initialize(self):
        from alembic import command
        from alembic.config import Config
        config = Config()
        config.set_main_option('script_location', str(Path(__file__).parent / 'migrations'))
        config.set_main_option('sqlalchemy.url', self.engine.url.render_as_string(hide_password=False))
        command.upgrade(config, 'head')
        with self.session() as db:
            if db.get(Routing, 1) is None:
                db.add(Routing(id=1))

    @contextmanager
    def session(self):
        with self.Session.begin() as session:
            yield session

    def verify_admin(self, username: str, password: str) -> bool:
        from argon2.exceptions import VerifyMismatchError, VerificationError
        with self.session() as s:
            a = s.scalar(select(Admin).where(Admin.username == username))
            if not a:
                return False
            try:
                return hasher.verify(a.password_hash, password)
            except (VerifyMismatchError, VerificationError):
                return False

    def authenticate(self, username: str, password: str):
        from argon2.exceptions import VerifyMismatchError, VerificationError
        with self.session() as s:
            user = s.scalar(select(Client).where(Client.username == username, Client.enabled.is_(True)))
            if not user:
                return None
            try:
                if not hasher.verify(user.password_hash, password):
                    return None
            except (VerifyMismatchError, VerificationError):
                return None
            return {'id': user.id, 'name': user.name, 'username': user.username,
                    'max_connections': user.max_connections,
                    'pinned_server_id': user.pinned_server_id,
                    'allow_fallback': user.allow_fallback}

    def servers(self):
        with self.session() as db:
            return [dict(id=x.id, name=x.name, host=x.host, port=x.port,
                         username=x.username, key_file=x.key_file,
                         known_hosts_file=x.known_hosts_file, priority=x.priority,
                         weight=x.weight, enabled=x.enabled)
                    for x in db.scalars(select(SSHServer).order_by(SSHServer.priority, SSHServer.id))]

    def routing(self):
        with self.session() as s:
            x = s.get(Routing, 1)
            return dict(mode=x.mode, manual_server_id=x.manual_server_id,
                        auto_failback=x.auto_failback)

    def record_traffic(self, client_id: int, upload: int, download: int):
        with self.session() as s:
            user = s.get(Client, client_id)
            if user:
                user.total_connections += 1
                user.bytes_uploaded += upload
                user.bytes_downloaded += download
                user.last_active = utcnow()

    def audit(self, actor: str, action: str, detail: str = ''):
        with self.session() as s:
            s.add(Audit(actor=actor, action=action, detail=detail[:300]))

    def event(self, category: str, message: str):
        with self.session() as s:
            s.add(Event(category=category, message=message[:500]))
