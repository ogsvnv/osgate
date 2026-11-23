"""Persisted rolling ten-minute history of SSH TCP-probe latency."""
import asyncio
from datetime import timedelta, timezone, datetime
from pathlib import Path
import json
import re
import shutil
import subprocess

import httpx
import pytest
from sqlalchemy import select, func

from osgate.app import create_app
from osgate.database import Database, SSHLatencySample, utcnow
from osgate.dashboard_charts import DASHBOARD_CHARTS_JS
from .test_socks5 import free_port


def test_latency_samples_persist_after_database_reopen_and_expire(setup):
    cfg, db = setup
    now = utcnow()
    db.record_ssh_latency(1, 42.25, when=now - timedelta(minutes=4))
    db.record_ssh_latency(2, None, when=now - timedelta(minutes=1))
    db.record_ssh_latency(1, 12.5, when=now - timedelta(seconds=15))
    reopened = Database(cfg.database_url)
    samples = reopened.recent_ssh_latency(now=now)
    assert [row['server_id'] for row in samples] == [1, 2, 1]
    assert [row['latency_ms'] for row in samples] == [42.25, None, 12.5]
    assert all(row['time'].endswith('+00:00') for row in samples)
    # A later write evicts stale records.
    reopened.record_ssh_latency(1, 8.0, when=now + timedelta(minutes=7))
    rows = reopened.recent_ssh_latency(now=now + timedelta(minutes=7))
    assert [r['latency_ms'] for r in rows] == [None, 12.5, 8.0]


def test_expired_samples_purged_even_when_ssh_stays_offline(setup):
    _, db = setup
    now = utcnow()
    db.record_ssh_latency(1, 10.0, when=now - timedelta(minutes=12))
    db.record_ssh_latency(1, 20.0, when=now)
    db.purge_ssh_latency()
    with db.session() as s:
        assert s.scalar(select(func.count(SSHLatencySample.id))) == 1


@pytest.mark.parametrize('value', [-5, float('nan'), float('inf'), float('-inf')])
def test_bad_latency_is_stored_as_missing_measurement(setup, value):
    _, db = setup
    db.record_ssh_latency(1, value)
    assert db.recent_ssh_latency()[-1]['latency_ms'] is None


@pytest.mark.asyncio
async def test_ssh_latency_api_requires_admin_and_recovers_history(setup):
    cfg, db = setup
    cfg.socks_port = await free_port()
    now=utcnow()
    db.record_ssh_latency(1, 22.0, when=now - timedelta(seconds=20))
    db.record_ssh_latency(2, None, when=now - timedelta(seconds=10))
    app = create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=('127.0.0.1',49921)),
            base_url='http://127.0.0.1'
        ) as http:
            assert (await http.get('/api/ssh-latency')).status_code == 401
            login = await http.get('/login')
            csrf = re.search(r'name="csrf" value="([^"]+)"', login.text).group(1)
            assert (await http.post('/login', data={
                'csrf': csrf,'username':'admin','password':'secret-admin-password'})).status_code==303
            result=await http.get('/api/ssh-latency')
            assert result.status_code==200
            assert result.headers['cache-control']=='no-store'
            assert result.json()['window_seconds']==600
            samples=result.json()['samples']
            assert len(samples)==2
            assert [x['server_id'] for x in samples]==[1,2]
            assert [x['latency_ms'] for x in samples]==[22.0,None]
            overview=await http.get('/')
            assert "fetch('/api/ssh-latency',{cache:'no-store'})" in overview.text
            assert "renderDashboardLatency(s,await c.json());" in overview.text


def test_migration_revision_is_registered(setup):
    cfg, db=setup
    with db.engine.connect() as conn:
        revision=conn.exec_driver_sql('select version_num from alembic_version').scalar()
        assert revision=='0004'
        assert db.engine.dialect.has_table(conn,'ssh_latency_samples')


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js optional')
def test_ten_minute_plot_uses_persisted_samples_and_missing_values():
    # No DOM needed: lightweight stubs capture chart series for assertions.
    harness = DASHBOARD_CHARTS_JS + """
      const now=Date.now();
      let plotted=null;
      const canvas={getBoundingClientRect(){return {width:500}},
          getContext(){return null}};
      global.document={
        getElementById(id){
          if(id==='dashboard-ping-chart')return canvas;
          if(id==='dashboard-ping-legend')
              return {replaceChildren(){},appendChild(){}};
          if(id==='dashboard-ping-caption')return {textContent:''};
          return {};
        },
        createElement(){return {style:{},textContent:''}}
      };
      const actualPlot=dashboardPlot;
      dashboardPlot=function(canvas, series,unit,labels){
        plotted={series,unit,labels};
      };
      const response={samples:[
        {server_id:1,time:new Date(now-400000).toISOString(),latency_ms:50},
        {server_id:1,time:new Date(now-240000).toISOString(),latency_ms:null},
        {server_id:1,time:new Date(now-15000).toISOString(),latency_ms:12},
        {server_id:2,time:new Date(now-15000).toISOString(),latency_ms:25},
        {server_id:1,time:new Date(now-700000).toISOString(),latency_ms:999}
      ]};
      renderDashboardLatency({ssh_servers:[
        {id:1,name:'gamma-5'},{id:2,name:'park'}]}, response);
      if(plotted.series.length!==2||plotted.series[0].values.length!==21)
          throw Error('wrong history');
      const a=plotted.series[0].values;
      if(!a.some(x=>x===50)||!a.some(x=>x===12)||a.some(x=>x===999))
          throw Error('wrong time window');
      if(a.filter(x=>x===null).length<1)throw Error('missing gap');
      if(plotted.unit!=='мс')throw Error('wrong unit');
      console.log('ok');
    """
    proc=subprocess.run(['node','-e',harness],capture_output=True,text=True)
    assert proc.returncode==0,proc.stderr
    assert 'ok' in proc.stdout
