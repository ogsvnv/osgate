"""Non-blocking, rate-limited Telegram notifications."""
import asyncio
import logging
import time
import httpx
log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, settings):
        self.settings = settings
        self._last = {}
        self.tasks = set()

    async def notify(self, category, message):
        if not (self.settings.telegram_enabled and self.settings.telegram_bot_token and
                self.settings.telegram_chat_id):
            return
        key = (category, message)
        now = time.monotonic()
        if now - self._last.get(key, 0) < 60:
            return
        self._last[key] = now
        task = asyncio.create_task(self._send(f'OSGate [{category}]\n{message}'))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _send(self, text):
        try:
            async with httpx.AsyncClient(timeout=8) as session:
                await session.post(
                    f'https://api.telegram.org/bot{self.settings.telegram_bot_token}/sendMessage',
                    json={'chat_id': self.settings.telegram_chat_id, 'text': text})
        except Exception:
            log.warning('Telegram message delivery failed')

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
