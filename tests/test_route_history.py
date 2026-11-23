"""End-to-end routing event audit: migration, persistence, selection and UI."""
from datetime import timedelta
import csv
import io
import re
import httpx
import pytest
from sqlalchemy import select, func

from osgate.app import create_app
from osgate.database import Database, SSHServer, RouteEvent, utcnow
from osgate.route_history import RouteHistoryTracker
from .test_socks5 import free_port


def ready(server_id, priority=100, delay=30, status=True):
    return dict(id=server_id, name=f'server-{server_id}', ready=status,
                latency_ms=delay, priority=priority, weight=1)


def test_events_persist_migration_filter_and_retention(setup):
    cfg, db = setup
    with db.engine.connect() as conn:
        assert conn.exec_driver_sql('select version_num from alembic_version').scalar() == '0004'
        assert db.engine.dialect.has_table(conn, 'route_events')
    with db.session() as session:
        session.add_all([
            SSHServer(name='gamma-5', host='example1', username='user',
                      key_file='fake', known_hosts_file='fake'),
            SSHServer(name='gamma-6', host='example2', username='user',
                      key_file='fake', known_hosts_file='fake')
        ])
    now = utcnow()
    db.record_route_event(from_server_id=1, to_server_id=2, mode='failover',
                          reason='offline', details={'old_rtt_ms':None,'new_rtt_ms':35.1},
                          when=now-timedelta(hours=2))
    db.record_route_event(from_server_id=2, to_server_id=1, mode='failover',
                          reason='recovered', when=now-timedelta(minutes=2))
    db.record_route_event(from_server_id=1, to_server_id=2, mode='min_rtt',
                          reason='lower_rtt', when=now-timedelta(days=9))
    reopened = Database(cfg.database_url)
    events = reopened.recent_route_events(hours=24)
    assert events['total'] == 2
    assert [x['reason'] for x in events['events']] == ['recovered','offline']
    assert events['events'][0]['from_name'] == 'gamma-6'
    assert events['events'][0]['to_name'] == 'gamma-5'
    assert events['events'][1]['details']['new_rtt_ms'] == 35.1
    assert reopened.recent_route_events(hours=1)['total'] == 1
    assert reopened.recent_route_events(hours=24, server_id=1)['total'] == 2
    assert reopened.recent_route_events(hours=24, server_id=3)['total'] == 0
    assert reopened.recent_route_events(hours=24, reason='offline')['total'] == 1
    assert reopened.recent_route_events(hours=24, offset=1, limit=1)['events'][0]['reason'] == 'offline'
    stats = reopened.route_event_stats(now=now)
    assert (stats['total'],stats['emergency'],stats['recovery']) == (2,1,1)
    reopened.purge_route_events()
    with reopened.session() as session:
        assert session.scalar(select(func.count(RouteEvent.id))) == 2


def test_route_tracker_stable_rtt_and_no_per_connection_spam(setup):
    _,db=setup
    tracker=RouteHistoryTracker(db)
    online=[ready(1,delay=55),ready(2,delay=20)]
    tracker.observe(mode='min_rtt',selected=1,available=online,preferred_id=1)
    for _ in range(50):
        tracker.observe(mode='min_rtt',selected=1,available=online,preferred_id=1)
    assert db.recent_route_events()['total']==0
    tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    assert db.recent_route_events()['total']==0
    tracker.observe(mode='min_rtt',selected=1,available=online,preferred_id=1)
    tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    assert db.recent_route_events()['total']==1
    assert db.recent_route_events()['events'][0]['reason']=='lower_rtt'
    for _ in range(20):
        tracker.observe(mode='min_rtt',selected=2,available=online,preferred_id=2)
    assert db.recent_route_events()['total']==1


def test_route_tracker_failover_recovery_and_no_round_robin_noise(setup):
    _,db=setup
    tracker=RouteHistoryTracker(db)
    online=[ready(1,priority=1),ready(2,priority=2)]
    tracker.observe(mode='failover',selected=1,available=online,preferred_id=1)
    online[0]['ready']=False
    tracker.observe(mode='failover',selected=2,available=online,preferred_id=2)
    online[0]['ready']=True
    tracker.observe(mode='failover',selected=1,available=online,preferred_id=1)
    assert [x['reason'] for x in db.recent_route_events()['events']] == ['recovered','offline']
    tracker.observe(mode='round_robin',selected=2,available=online,preferred_id=2)
    tracker.observe(mode='round_robin',selected=1,available=online,preferred_id=1)
    assert db.recent_route_events()['total']==2
    tracker.observe(mode='failover',selected=1,available=online,preferred_id=1)
    assert db.recent_route_events()['total']==2


def test_route_tracker_failed_primary_forwarding(setup):
    _,db=setup
    tracker=RouteHistoryTracker(db)
    online=[ready(1),ready(2)]
    tracker.observe(mode='failover',selected=1,available=online,preferred_id=1)
    tracker.observe(mode='failover',selected=2,available=online,preferred_id=1)
    assert db.recent_route_events()['events'][0]['reason']=='forwarding_failed'


@pytest.mark.asyncio
async def test_route_history_admin_apis_filters_csv_and_mode_changes(setup):
    cfg,db=setup
    cfg.socks_port=await free_port()
    with db.session() as session:
        session.add_all([
            SSHServer(name='gamma-5',host='example1',username='user',
                      key_file='fake',known_hosts_file='fake'),
            SSHServer(name='park',host='example2',username='user',
                      key_file='fake',known_hosts_file='fake')])
    db.record_route_event(from_server_id=1,to_server_id=2,
                          reason='offline',mode='failover',
                          details={'old_rtt_ms': 100.0,'new_rtt_ms': 21.0})
    app=create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49013)),
            base_url='http://127.0.0.1') as http:
            for path in ('/route-history','/api/route-events','/route-history.csv'):
                assert (await http.get(path)).status_code==401
            login=await http.get('/login')
            token=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            assert (await http.post('/login',data={'csrf':token,'username':'admin',
                    'password':'secret-admin-password'})).status_code==303
            page=await http.get('/')
            assert 'История переключений маршрутов' in page.text
            assert '/route-history' in page.text
            full=await http.get('/route-history')
            assert full.status_code==200
            assert 'История маршрутов' in full.text
            assert 'gamma-5' in full.text and 'park' in full.text
            assert 'SSH недоступен' in full.text
            assert '100.0' in full.text
            assert 'Вся история' in page.text
            api=await http.get('/api/route-events?limit=5')
            assert api.status_code==200
            assert api.headers['cache-control']=='no-store'
            assert api.json()['events'][0]['reason']=='offline'
            assert (await http.get('/api/route-events?reason=unlisted')).status_code==400
            assert (await http.get('/api/route-events?hours=45')).status_code==400
            assert (await http.get('/api/route-events?limit=5000')).status_code==400
            assert (await http.get('/api/route-events?server_id=2')).json()['total']==1
            assert (await http.get('/api/route-events?server_id=3')).json()['total']==0
            report=await http.get('/route-history.csv?hours=24')
            assert report.status_code==200
            assert 'attachment;' in report.headers['content-disposition']
            contents=list(csv.reader(io.StringIO(report.text)))
            assert contents[1][1:3]==['gamma-5','park']
            assert contents[1][3]=='SSH недоступен'
            csrf=re.search(r'name="csrf" value="([^"]+)"',page.text).group(1)
            assert (await http.post('/routing',data={'csrf':'bad','mode':'min_rtt'})).status_code==403
            assert (await http.post('/routing',data={'csrf':csrf,'mode':'min_rtt'})).status_code==303
            assert db.routing()['mode']=='min_rtt'
            last=db.recent_route_events()['events'][0]
            assert last['reason']=='mode_changed'
            assert last['actor']=='admin'
            assert last['details']['new_mode']=='min_rtt'
            # Reposting the same mode does not generate another history event.
            await http.post('/routing',data={'csrf':csrf,'mode':'min_rtt'})
            assert db.recent_route_events()['total']==2

def test_upgrade_existing_revision_0003_keeps_previous_tables(tmp_path):
    from sqlalchemy import text
    path=tmp_path/'existing.db'
    db=Database('sqlite:///'+str(path))
    db.initialize()
    # Simulate the previous release's exact migration state: the preexisting
    # schema has other tables and no route_events yet.
    with db.engine.begin() as connection:
        connection.exec_driver_sql('DROP TABLE route_events')
        connection.exec_driver_sql("UPDATE alembic_version SET version_num='0003'")
        connection.exec_driver_sql(
            'INSERT INTO events (category, message, "when") VALUES '
            "('TEST', 'preserve-existing-event', CURRENT_TIMESTAMP)")
    db.initialize()
    with db.engine.connect() as connection:
        assert connection.exec_driver_sql(
            'SELECT version_num FROM alembic_version').scalar()=='0004'
        assert connection.exec_driver_sql(
            "SELECT message FROM events WHERE category='TEST'").scalar() == 'preserve-existing-event'
        assert db.engine.dialect.has_table(connection,'route_events')
