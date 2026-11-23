"""Inline, dependency-free charts for the OSGate admin overview.

Traffic history is derived from persisted, cumulative 60s SQLite samples.
SSH RTT is the existing forwarded TCP health-probe latency (NOT ICMP ping).
"""
DASHBOARD_CHARTS_HTML = """
<div class="dashboard-charts">
  <section class="dashboard-chart">
    <h2>Трафик SOCKS5</h2>
    <p class="muted">Отправлено / получено, КиБ/с · история до 120 минут</p>
    <div class="chart-key"><span>● Отправлено</span><span>● Получено</span></div>
    <canvas id="dashboard-traffic-chart" height="220" role="img"
            aria-label="График скорости исходящего и входящего трафика"></canvas>
    <p class="muted" id="dashboard-traffic-caption" aria-live="off">Загрузка данных…</p>
  </section>
  <section class="dashboard-chart">
    <h2>Задержка SSH-серверов</h2>
    <p class="muted">Последние 10 минут · TCP через SSH (не ICMP ping)</p>
    <div class="chart-key" id="dashboard-ping-legend"></div>
    <canvas id="dashboard-ping-chart" height="220" role="img"
            aria-label="График задержки SSH-серверов"></canvas>
    <p class="muted" id="dashboard-ping-caption" aria-live="off">Загрузка данных…</p>
  </section>
</div>
"""

DASHBOARD_CHARTS_CSS = """
.dashboard-charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,400px),1fr));gap:16px}
.dashboard-charts section{min-width:0;margin:12px 0}
.dashboard-chart canvas{display:block;width:100%;height:220px}
.chart-key{display:flex;flex-wrap:wrap;gap:14px;font-size:13px;color:var(--soft)}
.chart-key span:nth-child(1){color:#7c9dff}
.chart-key span:nth-child(2){color:#59d394}
.chart-key span:nth-child(3){color:#edb95a}
.chart-key span:nth-child(4){color:#d68be9}
"""

# All runtime strings and SSH-server names are written with textContent,
# never innerHTML. No external libraries or CDN access needed.
DASHBOARD_CHARTS_JS = r"""
const DASHBOARD_PALETTE = ['#7c9dff','#59d394','#edb95a','#d68be9','#ed8888','#68cbd3'];

function dashboardPlot(canvas, series, unit, captions){
  const rect=canvas.getBoundingClientRect();
  const w=Math.max(200,rect.width),h=220,ratio=Math.min(2,window.devicePixelRatio||1);
  canvas.width=Math.round(w*ratio);canvas.height=Math.round(h*ratio);
  const ctx=canvas.getContext('2d');
  if(!ctx)return;
  ctx.setTransform(ratio,0,0,ratio,0,0);
  const l=46,r=12,t=16,b=30,pw=w-l-r,ph=h-t-b;
  ctx.clearRect(0,0,w,h);
  ctx.font='12px system-ui,sans-serif';
  ctx.textBaseline='middle';
  const color=getComputedStyle(canvas).color||'#a7b5cd';
  ctx.fillStyle=color;ctx.strokeStyle='rgba(140,150,170,.20)';
  let max=0,n=0;
  for(const s of series){
    n=Math.max(n,s.values.length);
    for(const v of s.values)if(Number.isFinite(v)&&v>=0)max=Math.max(max,v);
  }
  if(n<2 || !series.some(s=>s.values.some(v=>Number.isFinite(v)))){
    ctx.textAlign='center';ctx.fillText('Пока недостаточно данных',w/2,h/2);
    return;
  }
  const peak=Math.max(1,max*1.15);
  ctx.textAlign='right';
  for(let i=0;i<=4;i++){
    const y=t+ph*i/4,val=peak*(1-i/4);
    ctx.beginPath();ctx.moveTo(l,y);ctx.lineTo(l+pw,y);ctx.stroke();
    ctx.fillText(val>=100?Math.round(val):val.toFixed(1),l-7,y);
  }
  ctx.textAlign='left';ctx.fillText(unit,l,t-9);
  const ticks=[0,Math.floor((n-1)/2),n-1];
  ctx.textAlign='center';
  ticks.forEach(i=>{
    const x=l+pw*i/(n-1);
    ctx.fillText(captions?.[i]||'',x,h-12);
  });
  for(const item of series){
    ctx.strokeStyle=item.color;ctx.lineWidth=2;ctx.lineJoin='round';
    ctx.beginPath();let drawing=false;
    item.values.forEach((v,i)=>{
      if(!Number.isFinite(v)||v<0){drawing=false;return}
      const x=l+pw*i/(n-1),y=t+ph*(1-v/peak);
      if(!drawing)ctx.moveTo(x,y);else ctx.lineTo(x,y);
      drawing=true;
    });
    ctx.stroke();
  }
}
function dashboardTrafficSeries(samples,totalUp,totalDown){
  const rows=(samples||[]).filter(x=>Number.isFinite(Date.parse(x.time)));
  const plotted=[];
  for(let i=1;i<rows.length;i++){
    const previous=rows[i-1],current=rows[i];
    const dt=(Date.parse(current.time)-Date.parse(previous.time))/1000;
    if(!(dt>0))continue;
    const du=Number(current.uploaded)-Number(previous.uploaded);
    const dd=Number(current.downloaded)-Number(previous.downloaded);
    plotted.push({time:current.time,
      up:du>=0?du/dt/1024:null,down:dd>=0?dd/dt/1024:null});
  }
  // Unpersisted bytes from active connections: show a current partial-minute
  // rate without inventing historical traffic data.
  if(rows.length && Number.isFinite(totalUp) && Number.isFinite(totalDown)){
    const last=rows[rows.length-1],seconds=(Date.now()-Date.parse(last.time))/1000;
    if(seconds>2 && seconds<180){
      const du=totalUp-Number(last.uploaded),dd=totalDown-Number(last.downloaded);
      plotted.push({time:new Date().toISOString(),
        up:du>=0?du/seconds/1024:null,down:dd>=0?dd/seconds/1024:null});
    }
  }
  return plotted.slice(-120);
}
function renderDashboardTraffic(metrics){
  const pts=dashboardTrafficSeries(metrics.samples,metrics.uploaded,metrics.downloaded);
  const labels=pts.map(x=>new Date(x.time).toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'}));
  dashboardPlot(document.getElementById('dashboard-traffic-chart'),[
    {color:DASHBOARD_PALETTE[0],values:pts.map(x=>x.up)},
    {color:DASHBOARD_PALETTE[1],values:pts.map(x=>x.down)}
  ],'КиБ/с',labels);
  document.getElementById('dashboard-traffic-caption').textContent=
    pts.length?'Последняя точка: '+labels[labels.length-1]:'История трафика появится после двух замеров (интервал 60 с).';
}
function renderDashboardLatency(status,history){
  const active=Array.isArray(status.ssh_servers)?status.ssh_servers:[];
  const rows=active.slice(0,6);
  const samples=Array.isArray(history?.samples)?history.samples:[];
  const end=Date.now(),start=end-600000;
  // Fixed 10-minute time axis; samples grouped into 30-second buckets.
  // Missing or failed probes stay null, so no invented 0ms results.
  const slots=21;
  const bucketMs=30000;
  const series=rows.map((server,i)=>{
    const values=Array(slots).fill(null);
    for(const point of samples){
      if(String(point.server_id)!==String(server.id))continue;
      const timestamp=Date.parse(point.time);
      if(!Number.isFinite(timestamp)||timestamp<start||timestamp>end)continue;
      const slot=Math.min(slots-1,Math.floor((timestamp-start)/bucketMs));
      const ms=Number(point.latency_ms);
      values[slot]=point.latency_ms!==null&&Number.isFinite(ms)&&ms>=0?ms:null;
    }
    return {color:DASHBOARD_PALETTE[i],values};
  });
  const legend=document.getElementById('dashboard-ping-legend');
  legend.replaceChildren();
  rows.forEach((row,i)=>{
    const item=document.createElement('span');
    item.style.color=DASHBOARD_PALETTE[i];
    item.textContent='● '+String(row.name);
    legend.appendChild(item);
  });
  const labels=Array(slots).fill('');
  for(const i of [0,10,20]){
    labels[i]=new Date(start+i*bucketMs).toLocaleTimeString(
      'ru-RU',{hour:'2-digit',minute:'2-digit'});
  }
  dashboardPlot(document.getElementById('dashboard-ping-chart'),series,'мс',labels);
  document.getElementById('dashboard-ping-caption').textContent=rows.length?
    'История 10 минут сохраняется в SQLite и восстанавливается после обновления страницы. Пропуски означают отсутствие успешной проверки.':
    'Добавьте SSH-сервер для отображения задержки.';
}
"""
