from sqlalchemy import select
from osgate.database import Client
from osgate.routing import Router


def server(id, priority=100, weight=1, ready=True):
    return {'id': id, 'name': str(id), 'priority': priority, 'weight': weight, 'ready': ready}


def test_passwords_are_hashed(setup):
    _, db = setup
    with db.session() as s:
        u = s.scalar(select(Client).where(Client.username == 'browser'))
        assert u.password_hash != 'client-password-123'
        assert u.password_hash.startswith('$argon2id$')
    assert db.authenticate('browser', 'client-password-123')['id'] > 0
    assert db.authenticate('browser', 'wrong') is None
    assert db.verify_admin('admin', 'secret-admin-password')
    assert not db.verify_admin('browser', 'client-password-123')


def test_routing_modes_and_pin():
    r = Router()
    items = [server(1, 1, 3), server(2, 2, 1), server(3, 3, 1, False)]
    c = {'id': 42, 'pinned_server_id': None, 'allow_fallback': False}
    assert [x['id'] for x in r.candidates(items, {'mode': 'failover'}, c)] == [1, 2]
    assert [r.candidates(items, {'mode': 'round_robin'}, c)[0]['id'] for _ in range(4)] == [1, 2, 1, 2]
    r = Router()
    assert [r.candidates(items, {'mode': 'weighted_round_robin'}, c)[0]['id'] for _ in range(4)] == [1, 1, 1, 2]
    assert r.candidates(items, {'mode': 'manual', 'manual_server_id': 3}, c) == []
    c['pinned_server_id'] = 3
    assert r.candidates(items, {'mode': 'failover'}, c) == []
    c['allow_fallback'] = True
    assert [x['id'] for x in r.candidates(items, {'mode': 'failover'}, c)] == [1, 2]
