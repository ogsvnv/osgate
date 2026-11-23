"""Application lifecycle, with independent SSH and HTTP/SOCKS listeners."""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from .config import Settings
from .database import Database
from .ssh import SSHManager
from .socks5 import SocksServer
from .notifications import Notifier
from .web import register_routes

log = logging.getLogger(__name__)


class Runtime:
    def __init__(self, settings: Settings, db=None, connector=None):
        self.settings = settings
        self.db = db or Database(settings.database_url)
        self.notifier = Notifier(settings)
        self.ssh = SSHManager(self.db, settings, notify=self.notifier.notify, connector=connector)
        self.socks = SocksServer(self.db, self.ssh, settings)
        self._metrics_task = None
        self.started_at = time.monotonic()

    async def start(self):
        await asyncio.to_thread(self.db.initialize)
        from .settings_store import load_runtime_settings
        await asyncio.to_thread(load_runtime_settings, self.db, self.settings)
        await self.ssh.start()
        try:
            await self.socks.start()
        except Exception:
            await self.ssh.stop()
            raise
        self._metrics_task = asyncio.create_task(self._collect_metrics(), name='traffic-samples')
        await self.notifier.notify('SYSTEM', 'OSGate started')

    async def _collect_metrics(self):
        while True:
            try:
                await asyncio.to_thread(self.db.sample_traffic, len(self.socks.active),
                                        self.settings.traffic_retention_days)
            except Exception:
                log.exception('Traffic snapshot error')
            await asyncio.sleep(60)

    async def stop(self):
        if self._metrics_task:
            self._metrics_task.cancel()
            await asyncio.gather(self._metrics_task, return_exceptions=True)
            self._metrics_task = None
        await self.socks.stop()
        await self.ssh.stop()
        await self.notifier.notify('SYSTEM', 'OSGate stopped')
        await self.notifier.stop()


def create_app(settings: Settings | None = None, *, connector=None) -> FastAPI:
    settings = settings or Settings()
    settings.validate_runtime()
    logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO),
                        format='%(asctime)s %(levelname)s %(name)s %(message)s')
    runtime = Runtime(settings, connector=connector)

    @asynccontextmanager
    async def lifespan(app):
        app.state.login_attempts = {}
        await runtime.start()
        try:
            yield
        finally:
            await runtime.stop()

    app = FastAPI(title='OSGate', docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.state.runtime = runtime
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret,
                       session_cookie='osgate_session', max_age=3600, same_site='strict',
                       https_only=settings.web_secure_cookies)
    register_routes(app, runtime)
    return app
