"""Route new SOCKS5 connections via the lowest measured SSH TCP RTT."""
import math
import re

import httpx
import pytest

from osgate.app import create_app
from osgate.routing import Router
from .test_socks5 import free_port


def make_server(server_id, rtt, ready=True, priority=100):
    return dict(id=server_id, name=f"server-{server_id}",
                latency_ms=rtt, ready=ready, priority=priority, weight=1)


CLIENT = dict(id=100, pinned_server_id=None, allow_fallback=False)


def test_min_rtt_orders_healthy_servers_independently_of_priority():
    router = Router()
    servers = [
        make_server(1, 90, priority=1),
        make_server(2, 12.4, priority=300),
        make_server(3, 30, priority=100),
        make_server(4, 1, ready=False),
    ]
    chosen = router.candidates(servers, {'mode': 'min_rtt'}, CLIENT)
    assert [s['id'] for s in chosen] == [2, 3, 1]


def test_min_rtt_updates_order_for_new_connections():
    router = Router()
    servers = [make_server(1, 40), make_server(2, 20)]
    assert router.candidates(servers, {'mode': 'min_rtt'}, CLIENT)[0]['id'] == 2
    servers[0]['latency_ms'] = 9
    assert router.candidates(servers, {'mode': 'min_rtt'}, CLIENT)[0]['id'] == 1


@pytest.mark.parametrize('bad', [None, -1, float('nan'), float('inf'),
                                 float('-inf'), 'invalid', True])
def test_min_rtt_invalid_or_unavailable_measurements_last(bad):
    router = Router()
    servers = [make_server(1, bad), make_server(2, 20)]
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, CLIENT)] == [2, 1]


def test_min_rtt_all_unmeasured_have_stable_priority_order():
    router = Router()
    servers = [make_server(8, None, priority=10),
               make_server(7, None, priority=10),
               make_server(3, None, priority=5)]
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, CLIENT)] == [3, 7, 8]


def test_min_rtt_equal_ping_uses_priority_then_id():
    router = Router()
    servers = [make_server(5, 15.4, priority=10),
               make_server(2, 15.4, priority=10),
               make_server(8, 15.4, priority=1)]
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, CLIENT)] == [8, 2, 5]


def test_min_rtt_respects_client_pin_and_allow_fallback():
    router = Router()
    servers = [make_server(1, 8), make_server(2, 40),
               make_server(3, 20)]
    pinned = dict(CLIENT, pinned_server_id=2, allow_fallback=False)
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, pinned)] == [2]
    pinned['allow_fallback'] = True
    # Preserve existing pinned-client fallback ordering.
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, pinned)] == [2, 1, 3]
    servers[1]['ready'] = False
    assert [s['id'] for s in router.candidates(
        servers, {'mode': 'min_rtt'}, pinned)] == [1, 3]


def test_min_rtt_no_online_servers():
    router = Router()
    assert router.candidates([make_server(1, 8, ready=False)],
                             {'mode': 'min_rtt'}, CLIENT) == []


@pytest.mark.asyncio
async def test_min_rtt_mode_is_visible_and_persists_in_admin_panel(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=('127.0.0.1', 49931)),
            base_url='http://127.0.0.1'
        ) as client:
            assert (await client.get('/routing')).status_code == 401
            login = await client.get('/login')
            csrf = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            assert (await client.post('/login', data={
                'csrf': csrf, 'username': 'admin',
                'password': 'secret-admin-password'})).status_code == 303
            routing = await client.get('/routing')
            assert routing.status_code == 200
            assert '<option value="min_rtt"' in routing.text
            assert 'Минимальная задержка (RTT)' in routing.text
            csrf = re.search(r'name="csrf" value="([^"]+)"', routing.text).group(1)
            assert (await client.post('/routing', data={
                'csrf': 'incorrect', 'mode': 'min_rtt'})).status_code == 403
            saved = await client.post('/routing', data={
                'csrf': csrf, 'mode': 'min_rtt', 'auto_failback': 'yes'})
            assert saved.status_code == 303
            assert db.routing()['mode'] == 'min_rtt'
            selected = await client.get('/routing')
            assert '<option value="min_rtt" selected>' in selected.text
