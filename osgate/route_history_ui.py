"""Admin-only views of actual routing transitions, statistics and CSV export."""
from __future__ import annotations

import asyncio
import csv
import io
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from .database import RouteEvent
from .web import page, require_admin, safe


REASONS = {
    'offline': ('🔴', 'SSH недоступен', 'Аварийное'),
    'forwarding_failed': ('🔴', 'Ошибка TCP forwarding', 'Аварийное'),
    'recovered': ('🟢', 'Восстановление основного', 'Восстановление'),
    'lower_rtt': ('🟡', 'Меньшая задержка RTT', 'RTT'),
    'manual': ('🔵', 'Ручной выбор', 'Ручное'),
    'mode_changed': ('🔵', 'Режим изменён', 'Настройка'),
    'route_changed': ('🔵', 'Маршрут изменён', 'Система'),
}
MODES = {
    'failover': 'Failover', 'min_rtt': 'Минимальный RTT',
    'manual': 'Ручной', 'round_robin': 'Round Robin',
    'weighted_round_robin': 'Weighted Round Robin', 'sticky': 'Sticky',
}


def query_filters(request: Request):
    try:
        period = int(request.query_params.get('hours', '24'))
        offset = int(request.query_params.get('offset', '0'))
        raw_server = request.query_params.get('server_id', '')
        server_id = int(raw_server) if raw_server else None
    except ValueError as exc:
        raise HTTPException(400, 'Недопустимые параметры истории маршрутов') from exc
    reason = request.query_params.get('reason', '')
    if period not in (1, 24, 168) or offset < 0 or offset > 1000000:
        raise HTTPException(400, 'Недопустимые параметры истории маршрутов')
    if server_id is not None and not 1 <= server_id < 2**31:
        raise HTTPException(400, 'Недопустимый SSH-сервер')
    if reason and reason not in REASONS:
        raise HTTPException(400, 'Неизвестная причина переключения')
    return {'hours': period, 'offset': offset, 'server_id': server_id, 'reason': reason or None}


def row_view(event):
    from_text = event['from_name'] or (
        f"ID {event['from_server_id']}" if event['from_server_id'] is not None else '—')
    to_text = event['to_name'] or (
        f"ID {event['to_server_id']}" if event['to_server_id'] is not None else '—')
    icon, reason, group = REASONS.get(event['reason'], ('•', 'Событие', 'Система'))
    data = event['details']
    info = []
    for field, title in (
        ('old_rtt_ms','RTT до'), ('new_rtt_ms','RTT после'),
        ('old_mode','Режим до'), ('new_mode','Режим после'),
        ('previous_error','Последняя ошибка SSH')):
        if field in data and data[field] is not None:
            suffix = ' мс' if field.endswith('_ms') else ''
            info.append(f'<p><b>{safe(title)}:</b> {safe(data[field])}{suffix}</p>')
    info.append(f'<p><b>Источник:</b> {safe(event["actor"])}</p>')
    return dict(**event, from_text=from_text, to_text=to_text, icon=icon,
                reason_label=reason, category=group,
                mode_label=MODES.get(event['mode'], event['mode']),
                details_html=''.join(info))


def history_table(events, *, dom_id='route-history-table'):
    body = (f'<table id="{safe(dom_id)}"><thead><tr><th>Когда</th>'
            '<th>Откуда</th><th>Куда</th><th>Причина</th>'
            '<th>Режим</th><th>Подробности</th></tr></thead><tbody>')
    for raw in events:
        event = row_view(raw)
        body += ('<tr><td><time class="route-local-time" datetime="'
                 f'{safe(event["time"])}">{safe(event["time"])}</time></td>'
                 f'<td>{safe(event["from_text"])}</td>'
                 f'<td>{safe(event["to_text"])}</td>'
                 f'<td>{event["icon"]} {safe(event["reason_label"])}</td>'
                 f'<td>{safe(event["mode_label"])}</td>'
                 f'<td><details><summary>Открыть</summary>'
                 f'<p>Время UTC: {safe(event["time"])}</p>'
                 f'{event["details_html"]}</details></td></tr>')
    if not events:
        body += '<tr><td colspan="6">Пока нет событий за выбранный период.</td></tr>'
    return body + '</tbody></table>'


def safe_csv_field(value):
    # Prevent spreadsheet formula injection in user-provided SSH server names.
    value = str(value)
    if value and value.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + value
    return value


def time_script():
    return '''<script>
    function routeLocalTimes(){
      document.querySelectorAll('.route-local-time').forEach(el=>{
        const date=new Date(el.dateTime);
        if(!Number.isNaN(date.getTime()))
          el.textContent=date.toLocaleString('ru-RU');
      });
    }
    routeLocalTimes();
    </script>'''


def register_route_history_routes(app, runtime):
    db = runtime.db

    @app.get('/api/route-events')
    async def api_route_events(request: Request):
        require_admin(request)
        filters = query_filters(request)
        limit = request.query_params.get('limit', '50')
        try:
            count = int(limit)
        except ValueError as exc:
            raise HTTPException(400, 'Некорректный размер страницы') from exc
        if not 1 <= count <= 50:
            raise HTTPException(400, 'Некорректный размер страницы')
        records = await asyncio.to_thread(db.recent_route_events, **filters, limit=count)
        return JSONResponse(records, headers={'Cache-Control': 'no-store'})

    @app.get('/route-history')
    async def route_history_page(request: Request):
        require_admin(request)
        filters = query_filters(request)
        data, stats, servers = await asyncio.gather(
            asyncio.to_thread(db.recent_route_events, **filters, limit=50),
            asyncio.to_thread(db.route_event_stats),
            asyncio.to_thread(db.servers),
        )
        def option(value, selected, label):
            return (f'<option value="{safe(value)}"'
                    f'{" selected" if value==selected else ""}>{safe(label)}</option>')
        body = ('<section><p class="muted">Журнал фактических переключений '
                'глобального маршрута и изменений режима. Новое '
                'SOCKS5-подключение не означает отдельное переключение. '
                'В режиме минимального RTT изменение записывается после '
                'трёх последовательных подтверждений нового предпочтения. '
                'Маршруты закреплённых клиентов и Round Robin сюда не '
                'записываются как глобальные переключения.</p></section>')
        body += ('<div class="grid">'
                 f'<div class="card"><small>Событий за 24 ч</small><h2>{stats["total"]}</h2></div>'
                 f'<div class="card"><small>Аварийных</small><h2>{stats["emergency"]}</h2></div>'
                 f'<div class="card"><small>Восстановлений</small><h2>{stats["recovery"]}</h2></div>'
                 '<div class="card"><small>Последнее событие</small>'
                 f'<h2 id="last-route-event">{safe((stats['last'] if stats['last'].tzinfo else stats['last'].replace(tzinfo=timezone.utc)).isoformat() if stats['last'] else '—')}</h2></div>'
                 '</div>')
        body += '<section><form method="get" action="/route-history">'
        body += '<label>Период <select name="hours">'
        for hours, title in ((1,'1 час'),(24,'24 часа'),(168,'7 дней')):
            body += option(hours, filters['hours'], title)
        body += '</select></label><label>SSH-сервер <select name="server_id">'
        body += option('', '' if filters['server_id'] is None else filters['server_id'], 'Все')
        for server in servers:
            body += option(server['id'], filters['server_id'], server['name'])
        body += '</select></label><label>Причина <select name="reason">'
        body += option('', '' if filters['reason'] is None else filters['reason'], 'Все')
        for reason, (_, label, _) in REASONS.items():
            body += option(reason, filters['reason'], label)
        body += '</select></label><button>Применить</button></form>'
        args = {k:v for k,v in filters.items() if v is not None}
        args.pop('offset',None)
        body += (f'<p><a href="/route-history.csv?{safe(urlencode(args))}">'
                 'Экспорт CSV</a> · обновление каждые 5 секунд</p>')
        body += history_table(data['events'])
        page_no=filters['offset']
        if page_no:
            prev={**args,'offset':max(0,page_no-50)}
            body += f'<a href="/route-history?{safe(urlencode(prev))}">← Назад</a> '
        if page_no + 50 < data['total']:
            next_args={**args,'offset':page_no+50}
            body += f'<a href="/route-history?{safe(urlencode(next_args))}">Далее →</a>'
        body += '</section>'
        body += time_script()
        body += '''<script>
        const routeParams=new URLSearchParams(window.location.search);
        routeParams.set('limit','50');
        setInterval(async()=>{
          if(document.hidden || document.querySelector('details[open]'))return;
          try{
            const response=await fetch('/api/route-events?'+routeParams,
              {cache:'no-store'});
            if(!response.ok)return;
            const data=await response.json();
            // New events should be visible without reloading and losing filters.
            // Reload only when the first visible event changed.
            const first=document.querySelector('#route-history-table tbody time');
            if(first&&data.events.length&&first.dateTime!==data.events[0].time)
              location.reload();
          }catch(_){}
        },5000);
        const last=document.getElementById('last-route-event');
        if(last&&last.textContent!=='—'){
          const d=new Date(last.textContent);
          if(!Number.isNaN(d.getTime()))last.textContent=d.toLocaleString('ru-RU');
        }
        </script>'''
        return page(request, 'История маршрутов', body)

    @app.get('/route-history.csv')
    async def route_history_csv(request: Request):
        require_admin(request)
        filters = query_filters(request)
        filters.pop('offset',None)
        data = await asyncio.to_thread(db.recent_route_events, **filters, limit=10000)
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(['UTC', 'From', 'To', 'Reason', 'Mode', 'Actor',
                         'Old RTT ms', 'New RTT ms'])
        for raw in data['events']:
            event=row_view(raw)
            details=event['details']
            writer.writerow([safe_csv_field(v) for v in
                [event['time'],event['from_text'],event['to_text'],
                 event['reason_label'],event['mode_label'],event['actor'],
                 details.get('old_rtt_ms',''),details.get('new_rtt_ms','')]])
        return Response(stream.getvalue(),media_type='text/csv; charset=utf-8',
                        headers={'Cache-Control':'no-store',
                            'Content-Disposition':'attachment; filename="osgate-route-events.csv"'})
