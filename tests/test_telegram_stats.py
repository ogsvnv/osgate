"""SSH metrics and Telegram administration integration."""
import asyncio
from datetime import timedelta
import re

import httpx
import pytest

from osgate.app import create_app
from osgate.database import Database, utcnow
from osgate.notifications import Notifier, cipher
from .test_socks5 import free_port


def test_quality_stats_are_aggregated_and_bounded(setup):
    cfg, db = setup
    now = utcnow()
    db.record_ssh_latency(1, 20, when=now-timedelta(minutes=3))
    db.record_ssh_latency(1, None, when=now-timedelta(minutes=2))
    db.record_ssh_latency(1, 80, when=now-timedelta(minutes=1))
    db.record_ssh_latency(2, None, when=now-timedelta(seconds=30))
    db.record_ssh_latency(3, 100, when=now-timedelta(minutes=11))
    stats=Database(cfg.database_url).ssh_latency_stats(now=now)
    assert stats[1]['checks']==3
    assert stats[1]['success']==2
    assert stats[1]['failures']==1
    assert stats[1]['min_rtt_ms']==20
    assert stats[1]['avg_rtt_ms']==50
    assert stats[1]['max_rtt_ms']==80
    assert stats[1]['success_rate_percent']==66.7
    assert stats[1]['last_success'].endswith('+00:00')
    assert stats[2]['success_rate_percent']==0
    assert stats[2]['avg_rtt_ms'] is None
    assert 3 not in stats


@pytest.mark.asyncio
async def test_telegram_admin_flow_and_stats_api(setup, monkeypatch):
    cfg, db = setup
    cfg.socks_port=await free_port()
    app=create_app(cfg)
    calls=[]
    async def mock_send(self, message, **kwargs):
        calls.append(message)
        return True
    monkeypatch.setattr(Notifier,'_send',mock_send)
    token='123456789:'+'x'*35
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49093)),
            base_url='http://127.0.0.1') as h:
            assert (await h.get('/api/ssh-stats')).status_code==401
            assert (await h.get('/settings/telegram')).status_code==401
            login=await h.get('/login')
            csrf=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            await h.post('/login',data={
                'csrf':csrf,'username':'admin','password':'secret-admin-password'})
            main=await h.get('/')
            assert 'Качество SSH-серверов' in main.text
            assert "fetch('/api/ssh-stats',{cache:'no-store'})" in main.text
            assert (await h.get('/api/ssh-stats')).status_code==200
            assert (await h.get('/api/ssh-stats')).headers['cache-control']=='no-store'
            form=await h.get('/settings/telegram')
            assert 'Токен бота' in form.text
            csrf=re.search(r'name="csrf" value="([^"]+)"',form.text).group(1)
            assert (await h.post('/settings/telegram',data={
                'csrf':'bad','bot_token':token})).status_code==403
            assert (await h.post('/settings/telegram',data={
                'csrf':csrf,'bot_token':'bad','enabled':'yes'})).status_code==400
            assert (await h.post('/settings/telegram',data={
                'csrf':csrf,'enabled':'yes','chat_id':'-100123'})).status_code==400
            ok=await h.post('/settings/telegram',data={
                'csrf':csrf,'enabled':'yes','chat_id':'-100123',
                'bot_token':token,'event_ssh_offline':'yes',
                'event_route_failover':'yes'})
            assert ok.status_code==303
            content=(await h.get('/settings/telegram')).text
            assert token not in content
            assert '●●●● сохранён' in content
            assert '-100123' in content
            ciphered=db.get_setting('telegram_token_ciphertext')
            assert token not in ciphered
            assert cipher(cfg.session_secret).decrypt(ciphered.encode()).decode()==token
            assert app.state.runtime.notifier.events=={'ssh_offline','route_failover'}
            assert app.state.runtime.notifier.enabled
            result=await h.post('/settings/telegram/test',data={'csrf':csrf})
            assert 'Тестовое сообщение отправлено' in result.text
            assert len(calls)==1
            await h.post('/settings/telegram',data={
                'csrf':csrf,'enabled':'yes','chat_id':'-100123'})
            assert db.get_setting('telegram_token_ciphertext')==ciphered
            check=Notifier(cfg);check.load(db)
            assert check.token==token
            assert check.events==set()
            await h.post('/settings/telegram',data={
                'csrf':csrf,'chat_id':'','clear_token':'yes'})
            check.load(db)
            assert not check.enabled and not check.token


@pytest.mark.asyncio
async def test_event_filters_and_cooldown(setup,monkeypatch):
    cfg,_=setup
    bot=Notifier(cfg)
    bot.enabled=True
    bot.token='123456789:'+'x'*35
    bot.chat_id='-100123'
    bot.events={'ssh_offline','route_failover'}
    sent=[]
    async def fake_send(text,**kwargs):
        sent.append(text)
        return True
    monkeypatch.setattr(bot,'_send',fake_send)
    await bot.notify('SSH','gamma-5: OFFLINE')
    await bot.notify('SSH','gamma-5: OFFLINE')
    await bot.notify('SSH','gamma-5: ONLINE')
    await bot.notify_event('route_failover','gamma-5 → gamma-6')
    await asyncio.sleep(0.01)
    assert len(sent)==2
    await bot.stop()


def test_missing_key_disables_bot(setup):
    cfg, db=setup
    token='123456789:'+'x'*35
    db.set_settings({
        'telegram_enabled':'true',
        'telegram_token_source':'database',
        'telegram_token_ciphertext':cipher(cfg.session_secret).encrypt(token.encode()).decode(),
        'telegram_chat_id':'-100123',
    })
    cfg.session_secret='z'*64
    bot=Notifier(cfg);bot.load(db)
    assert not bot.enabled and not bot.token
