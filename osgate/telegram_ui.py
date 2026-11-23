"""Authenticated and CSRF-protected Telegram bot settings."""
from __future__ import annotations

import asyncio

from fastapi import HTTPException, Request

from .notifications import EVENTS, cipher, validate_bot_token, validate_chat_id
from .web import check_csrf, control, form_data, page, require_admin, return_to, safe


def register_telegram_routes(app, runtime):
    db = runtime.db
    notifier = runtime.notifier

    @app.get('/settings/telegram')
    async def telegram_settings(request: Request):
        require_admin(request)
        status = notifier.public_status()
        body = ('<section><h2>🤖 Уведомления Telegram</h2>'
                '<p class="muted">Для отправки сообщений создайте бота через @BotFather, '
                'получите токен и Chat ID получателя. Токен сохраняется '
                'зашифрованным и никогда не выводится на странице. '
                'Изменения применяются сразу, без перезапуска.</p>'
                f'<form method="post" action="/settings/telegram">{control(request)}'
                '<div class="stack">'
                '<label><input type="checkbox" name="enabled" value="yes" '
                + ('checked' if status['enabled'] else '')
                + '> Включить уведомления</label>'
                '<label>Токен бота '
                '<input type="password" name="bot_token" autocomplete="new-password" '
                'placeholder="Оставьте пустым, чтобы не менять" size="48"></label>'
                '<p class="muted">Токен: '
                + ('●●●● сохранён' if status['token_configured'] else 'не задан')
                + '</p>'
                '<label>Chat ID получателя '
                f'<input name="chat_id" value="{safe(status["chat_id"])}" '
                'autocomplete="off" maxlength="120" size="32"></label>'
                '<label><input type="checkbox" name="clear_token" value="yes"> '
                'Удалить сохранённый токен</label>'
                '</div><h3>Какие события отправлять</h3>')
        for kind, title in EVENTS.items():
            checked = ' checked' if kind in status['events'] else ''
            body += (f'<label style="display:block"><input type="checkbox" '
                     f'name="event_{safe(kind)}" value="yes"{checked}>'
                     f' {safe(title)}</label>')
        body += ('<p class="muted">Повтор одинакового события ограничен одним '
                 'уведомлением за 5 минут. Если Telegram недоступен, '
                 'работа SOCKS5 и SSH продолжается.</p>'
                 '<button>Сохранить настройки</button></form>'
                 f'<form method="post" action="/settings/telegram/test">{control(request)}'
                 '<button type="submit">Отправить тестовое сообщение</button>'
                 '</form></section>')
        return page(request, 'Настройки Telegram', body)

    @app.post('/settings/telegram')
    async def save_telegram_settings(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        token = data.get('bot_token', '').strip()
        chat_id = data.get('chat_id', '').strip()
        remove_token = data.get('clear_token') == 'yes'
        if token and remove_token:
            raise HTTPException(400, 'Нельзя одновременно менять и удалять токен')
        if token:
            try:
                validate_bot_token(token)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
        if chat_id:
            try:
                validate_chat_id(chat_id)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from None
        effective_token = '' if remove_token else (token or notifier.token)
        enabled = data.get('enabled') == 'yes'
        if enabled and (not effective_token or not chat_id):
            raise HTTPException(400, 'Для включения нужны токен и Chat ID')
        events = [kind for kind in EVENTS if data.get('event_' + kind) == 'yes']
        values = {
            'telegram_enabled': 'true' if enabled else 'false',
            'telegram_chat_id': chat_id,
            'telegram_events': ','.join(events) if events else 'none',
        }
        if token or remove_token:
            values['telegram_token_source'] = 'database'
        if token:
            values['telegram_token_ciphertext'] = cipher(
                runtime.settings.session_secret).encrypt(token.encode()).decode()
        elif remove_token:
            values['telegram_token_ciphertext'] = ''
        await asyncio.to_thread(db.set_settings, values)
        await asyncio.to_thread(notifier.load, db)
        await asyncio.to_thread(db.audit, request.session['admin'],
                                'telegram_config_update', 'settings')
        return return_to('/settings/telegram')

    @app.post('/settings/telegram/test')
    async def telegram_test(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        # A test is explicit and may be sent even when automatic events are disabled.
        if not (notifier.token and notifier.chat_id):
            return page(request, 'Проверка Telegram',
                        '<section><p>Сначала сохраните токен и Chat ID.</p>'
                        '<a href="/settings/telegram">Вернуться к настройкам</a></section>')
        success = await notifier.test()
        result = ('Тестовое сообщение отправлено.' if success else
                  'Не удалось доставить сообщение. Проверьте токен, Chat ID '
                  'и разрешение боту отправлять сообщения.')
        await asyncio.to_thread(db.audit, request.session['admin'],
                                'telegram_test', 'success' if success else 'failed')
        return page(request, 'Проверка Telegram',
                    f'<section><p>{safe(result)}</p>'
                    '<a href="/settings/telegram">Вернуться к настройкам</a></section>')
