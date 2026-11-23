"""Telegram delivery with explicit notification preferences, redacted secrets."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import time

import httpx
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)

EVENTS = {
    'ssh_offline': 'SSH-сервер недоступен',
    'ssh_online': 'SSH-сервер восстановлен',
    'route_failover': 'Аварийное переключение маршрута',
    'route_recovered': 'Восстановление основного маршрута',
    'route_rtt': 'Смена маршрута по RTT',
    'route_manual': 'Ручное переключение маршрута',
    'startup': 'Запуск OSGate',
}
DEFAULT_EVENTS = {'ssh_offline', 'ssh_online', 'route_failover',
                  'route_recovered', 'startup'}


def cipher(secret: str) -> Fernet:
    # Encryption is tied to the persisted SESSION_SECRET. Back up this value
    # together with the DB; changing it requires re-entering the bot token.
    key = base64.urlsafe_b64encode(
        hashlib.sha256(('osgate:telegram:token:v1:' + secret).encode()).digest())
    return Fernet(key)


def validate_bot_token(token: str):
    if not re.fullmatch(r'[0-9]{5,20}:[a-zA-Z0-9_-]{20,200}', token):
        raise ValueError('Некорректный формат токена Telegram-бота')


def validate_chat_id(chat_id: str):
    if not re.fullmatch(r'-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32}', chat_id):
        raise ValueError('Некорректный Chat ID')


class Notifier:
    def __init__(self, settings):
        self.settings = settings
        self._last = {}
        self.tasks = set()
        self.enabled = settings.telegram_enabled
        self.token = settings.telegram_bot_token
        self.chat_id = settings.telegram_chat_id
        self.events = set(DEFAULT_EVENTS)
        # httpx normally logs full request URLs (Telegram Bot API has token in
        # path), so suppress its request-level log records globally.
        logging.getLogger('httpx').setLevel(logging.WARNING)

    def load(self, db):
        enabled = db.get_setting('telegram_enabled', '')
        self.enabled = enabled == 'true' if enabled else self.settings.telegram_enabled
        self.chat_id = db.get_setting('telegram_chat_id', self.settings.telegram_chat_id)
        selected = db.get_setting('telegram_events', '')
        self.events = (set(selected.split(',')) & EVENTS.keys()
                       if selected else set(DEFAULT_EVENTS))
        encrypted = db.get_setting('telegram_token_ciphertext', '')
        if encrypted:
            try:
                self.token = cipher(self.settings.session_secret).decrypt(
                    encrypted.encode()).decode()
            except (InvalidToken, ValueError):
                self.token = ''
                self.enabled = False
                log.warning('Telegram token could not be decrypted; reconfigure it in admin UI')
        elif db.get_setting('telegram_token_source', '') == 'database':
            self.token = ''
        else:
            self.token = self.settings.telegram_bot_token

    def public_status(self):
        return {'enabled': self.enabled, 'token_configured': bool(self.token),
                'chat_id': self.chat_id, 'events': sorted(self.events)}

    async def notify(self, category, message):
        if category == 'SSH':
            if message.endswith(': ONLINE'):
                return await self.notify_event('ssh_online', message)
            if message.endswith(': OFFLINE'):
                return await self.notify_event('ssh_offline', message)
            return
        if category == 'SYSTEM' and message == 'OSGate started':
            return await self.notify_event('startup', message)

    async def notify_event(self, kind, message):
        if kind not in EVENTS or kind not in self.events:
            return
        if not (self.enabled and self.token and self.chat_id):
            return
        key = (kind, message)
        now = time.monotonic()
        if now - self._last.get(key, -1e6) < 300:
            return
        self._last[key] = now
        task = asyncio.create_task(self._send(f'OSGate • {EVENTS[kind]}\n{message}'))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _send(self, message, *, token=None, chat_id=None):
        value = token if token is not None else self.token
        destination = chat_id if chat_id is not None else self.chat_id
        try:
            async with httpx.AsyncClient(timeout=8, trust_env=False) as session:
                response = await session.post(
                    f'https://api.telegram.org/bot{value}/sendMessage',
                    json={'chat_id': destination, 'text': message})
                return bool(response.is_success and response.json().get('ok'))
        except (httpx.HTTPError, ValueError, KeyError):
            log.warning('Telegram message delivery failed')
            return False

    async def test(self):
        if not self.token or not self.chat_id:
            return False
        return await self._send('✅ OSGate: тестовое уведомление.')

    async def stop(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
