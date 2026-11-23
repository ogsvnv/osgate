"""Traffic counters must use readable units on initial and live render."""
import re
import shutil
import subprocess

import httpx
import pytest

from osgate.app import create_app
from osgate.traffic_format import human_bytes, human_uptime
from .test_socks5 import free_port


@pytest.mark.parametrize('value,expected', [
    (0,'0 Б'), (999,'999 Б'), (1023,'1023 Б'),
    (1024,'1,0 КБ'), (1536,'1,5 КБ'),
    (1356668,'1,3 МБ'), (2643627,'2,5 МБ'),
    (1024**2,'1,0 МБ'), (1024**3,'1,0 ГБ'),
    (1024**4,'1,0 ТБ'), (-10,'0 Б'),
    (None,'—')
])
def test_human_bytes(value,expected):
    assert human_bytes(value)==expected


@pytest.mark.asyncio
async def test_overview_uses_units_and_preserves_bytes_in_api(setup):
    cfg,db=setup
    cfg.socks_port=await free_port()
    app=create_app(cfg)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app,client=('127.0.0.1',49390)),
            base_url='http://127.0.0.1') as h:
            login=await h.get('/login')
            token=re.search(r'name="csrf" value="([^"]+)"',login.text).group(1)
            await h.post('/login', data={
                'csrf':token,'username':'admin','password':'secret-admin-password'})
            page=await h.get('/')
            assert 'Отправлено</small><h2>' in page.text
            assert 'Получено</small><h2>' in page.text
            assert 'function humanBytes(value)' in page.text
            assert 'humanBytes(m.uploaded),humanBytes(m.downloaded)' in page.text
            assert 'humanUptime(s.uptime_seconds)' in page.text
            assert 'Время работы</small><h2>' in page.text
            assert (await h.get('/api/metrics')).status_code==200
            assert isinstance((await h.get('/api/metrics')).json()['uploaded'],int)


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js optional')
def test_live_browser_formatting():
    from osgate.web import register_routes
    from pathlib import Path
    s=(Path(__file__).parents[1]/'osgate/web.py').read_text()
    fn=s.split('function humanBytes(value){',1)[1].split('async function updateDashboard()',1)[0]
    script='function humanBytes(value){'+fn+"""
      const cases=[
        [0,'0 Б'],[1536,'1,5 КБ'],[1356668,'1,3 МБ'],
        [2643627,'2,5 МБ'],[1073741824,'1,0 ГБ']
      ];
      for(const [num,expected] of cases){
        if(humanBytes(num)!==expected){
          throw Error(num+' expected '+expected+' got '+humanBytes(num));
        }
      }
    """
    p=subprocess.run(['node','-e',script],capture_output=True,text=True)
    assert p.returncode==0,p.stderr


@pytest.mark.parametrize('seconds,expected', [
    (0,'0 сек'),(59,'59 сек'),(60,'1 мин 0 сек'),(521,'8 мин 41 сек'),
    (3600,'1 ч'),(3661,'1 ч 1 мин'),(86400,'1 дн.'),
    (2*86400+3*3600+34*60,'2 дн. 3 ч 34 мин'),
    (-1,'0 сек'),(None,'—')
])
def test_human_uptime(seconds,expected):
    assert human_uptime(seconds)==expected


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js optional')
def test_live_browser_uptime_formatting():
    from pathlib import Path
    source=(Path(__file__).parents[1]/'osgate/web.py').read_text()
    fn=source.split('function humanUptime(seconds){',1)[1].split('async function updateDashboard()',1)[0]
    js='function humanUptime(seconds){'+fn+"""
      const cases=[[521,'8 мин 41 сек'],[0,'0 сек'],
        [185640,'2 дн. 3 ч 34 мин'],[3600,'1 ч']];
      for(const [n,expected] of cases){
        if(humanUptime(n)!==expected)
          throw Error(n+' '+humanUptime(n)+' != '+expected);
      }
    """
    output=subprocess.run(['node','-e',js],capture_output=True,text=True)
    assert output.returncode==0,output.stderr
