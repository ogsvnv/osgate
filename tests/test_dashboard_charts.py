"""Main dashboard charts: authenticated delivery, correct data and JS behavior."""
import json
import re
import shutil
import subprocess

import httpx
import pytest
from sqlalchemy import select

from osgate.app import create_app
from osgate.dashboard_charts import DASHBOARD_CHARTS_HTML, DASHBOARD_CHARTS_JS
from osgate.database import TrafficSample
from .test_socks5 import free_port


@pytest.mark.asyncio
async def test_charts_are_on_main_dashboard_and_authenticated(setup):
    cfg,db=setup
    cfg.socks_port=await free_port()
    app=create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49001)),
            base_url='http://127.0.0.1'
        ) as client:
            assert (await client.get('/')).status_code==401
            login=await client.get('/login')
            token=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            await client.post('/login',data={
                'csrf':token,'username':'admin','password':'secret-admin-password'})
            main=await client.get('/')
            assert main.status_code==200
            assert 'id="dashboard-traffic-chart"' in main.text
            assert 'id="dashboard-ping-chart"' in main.text
            assert 'Трафик SOCKS5' in main.text
            assert 'Задержка SSH-серверов' in main.text
            assert 'не ICMP ping' in main.text
            assert 'updateDashboard();setInterval(updateDashboard,5000);' in main.text
            assert "renderDashboardTraffic(m);" in main.text
            assert "renderDashboardLatency(s,await c.json());" in main.text
            assert "fetch('/api/ssh-latency',{cache:'no-store'})" in main.text
            assert "fetch('/api/metrics',{cache:'no-store'})" in main.text
            assert "fetch('/api/status',{cache:'no-store'})" in main.text
            assert 'https://cdn' not in main.text
            assert (await client.get('/api/metrics')).status_code==200
            assert (await client.get('/api/status')).status_code==200


def test_sample_timestamps_are_utc_for_browser_rate_calculation(setup):
    _,db=setup
    db.sample_traffic(0)
    samples=db.recent_samples()
    assert samples
    assert samples[-1]['time'].endswith('+00:00')


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js optional for JS syntax test')
def test_dashboard_javascript_has_valid_syntax_and_rates():
    # Run JS in Node without network access. Simulates 60-second persisted
    # samples and confirms negative counter resets never become negative rates.
    harness = DASHBOARD_CHARTS_JS + """
    const rows=[
       {time:'2026-11-24T10:00:00+00:00',uploaded:1024,downloaded:2048},
       {time:'2026-11-24T10:01:00+00:00',uploaded:62464,downloaded:124928},
       {time:'2026-11-24T10:02:00+00:00',uploaded:100,downloaded:50}
    ];
    const got=dashboardTrafficSeries(rows,NaN,NaN);
    if(got.length!==2)throw Error('expected 2 deltas');
    if(Math.abs(got[0].up-1)>1e-8 || Math.abs(got[0].down-2)>1e-8)
        throw Error('incorrect KiB/s rate');
    if(got[1].up!==null || got[1].down!==null)
        throw Error('counter reset must render gap');
    console.log(JSON.stringify(got));
    """
    result=subprocess.run(['node','-e',harness],capture_output=True,text=True)
    assert result.returncode==0, result.stderr
    points=json.loads(result.stdout)
    assert points[0]['up']==1
    assert points[0]['down']==2


def test_dashboard_html_has_accessible_canvas_labels():
    assert 'aria-label="График скорости исходящего и входящего трафика"' in DASHBOARD_CHARTS_HTML
    assert 'aria-label="График задержки SSH-серверов"' in DASHBOARD_CHARTS_HTML
    assert '10 минут' in DASHBOARD_CHARTS_HTML
