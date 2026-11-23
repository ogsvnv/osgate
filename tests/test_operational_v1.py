import asyncio
import re
import httpx
import pytest
from osgate.app import create_app
from osgate.config import Settings
from osgate.database import Database, SSHServer
from osgate.settings_store import EDITABLE, persist_runtime_settings, load_runtime_settings
from osgate.routing import Router
from osgate.ssh import SSHManager
from .test_socks5 import free_port


def test_settings_persistence_and_traffic_samples(setup):
    cfg, db = setup
    values = {k: str(getattr(cfg, k)) for k in EDITABLE}
    values['health_check_interval'] = '2.5'
    values['socks_max_connections'] = '17'
    persist_runtime_settings(db, cfg, values)
    other = Settings(session_secret='x'*64,database_url=cfg.database_url)
    load_runtime_settings(Database(cfg.database_url), other)
    assert (other.health_check_interval,other.socks_max_connections) == (2.5,17)
    db.sample_traffic(3)
    assert db.recent_samples()[-1]['active'] == 3
    with pytest.raises(ValueError):
        persist_runtime_settings(db,cfg,{**values,'health_check_interval':'-1'})


@pytest.mark.asyncio
async def test_session_revocation_and_runtime_settings(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=('127.0.0.1',49200)),
                                     base_url='http://127.0.0.1') as h:
            token = re.search(r'name="csrf" value="([^"]+)"',(await h.get('/login')).text).group(1)
            assert (await h.post('/login',data={'csrf':token,'username':'admin','password':'secret-admin-password'})).status_code==303
            token = re.search(r'name="csrf" value="([^"]+)"',(await h.get('/')).text).group(1)
            settings={k:str(getattr(cfg,k)) for k in EDITABLE}
            settings['health_check_interval']='3.0'
            assert (await h.post('/settings/runtime',data={**settings,'csrf':token})).status_code==303
            assert db.get_setting('health_check_interval')=='3.0'
            assert (await h.post('/settings/runtime',data={**settings,'csrf':token,
                                           'health_check_interval':'-1'})).status_code==400
            db.revoke_admin_sessions()
            assert (await h.get('/api/metrics')).status_code==401
            token=re.search(r'name="csrf" value="([^"]+)"',(await h.get('/login')).text).group(1)
            assert (await h.post('/login',data={'csrf':token,'username':'admin',
                                           'password':'secret-admin-password'})).status_code==303
            assert (await h.get('/api/metrics')).status_code==200


@pytest.mark.asyncio
async def test_ssh_does_not_route_before_health_success(setup):
    cfg, db = setup
    cfg.health_check_interval=0.01
    cfg.health_failure_threshold=3
    cfg.health_success_threshold=2
    with db.session() as s:
        s.add(SSHServer(name='test',host='test',username='user',port=22,
                        key_file='/ssh/key',known_hosts_file='/ssh/hosts'))
    class Conn:
        attempts=0
        closed=False
        def is_closed(self):return self.closed
        async def open_connection(self,host,port):
            self.attempts+=1
            await asyncio.sleep(0.03)
            if self.attempts<=2:raise ConnectionError('test')
            class Writer:
                def close(self):pass
            return None,Writer()
        def close(self):self.closed=True
        async def wait_closed(self):pass
    c=Conn()
    async def connector(record,settings):return c
    manager=SSHManager(db,cfg,connector=connector)
    await manager.start()
    try:
        for _ in range(100):
            if manager.states and manager.states[1].connection:break
            await asyncio.sleep(0.01)
        assert not manager.candidates()[0]['ready']
        await asyncio.sleep(0.035)
        assert not manager.candidates()[0]['ready']
        for _ in range(200):
            if manager.candidates()[0]['ready']:break
            await asyncio.sleep(0.01)
        assert manager.candidates()[0]['ready']
    finally:
        await manager.stop()


def test_failback_policy():
    router=Router()
    def server(id,priority,ready=True):
        return dict(id=id,name=str(id),priority=priority,weight=1,ready=ready)
    client=dict(id=1,pinned_server_id=None,allow_fallback=False)
    policy=dict(mode='failover',auto_failback=False,failback_delay=0)
    assert router.candidates([server(1,1),server(2,2)],policy,client)[0]['id']==1
    assert router.candidates([server(1,1,False),server(2,2)],policy,client)[0]['id']==2
    assert router.candidates([server(1,1),server(2,2)],policy,client)[0]['id']==2
    policy['auto_failback']=True
    assert router.candidates([server(1,1),server(2,2)],policy,client)[0]['id']==1
