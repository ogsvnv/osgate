"""Russian-language administrative UI with separate authorization and CSRF checks."""
import asyncio
import ipaddress
import secrets
from datetime import datetime, timezone
from html import escape
from urllib.parse import parse_qs

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jinja2 import Environment, BaseLoader, select_autoescape
from sqlalchemy import select, desc

from .database import Admin, Client, SSHServer, Routing, Event, Audit, hasher
from .routing import MODES
from .ssh import connect_ssh
from .dashboard_charts import DASHBOARD_CHARTS_HTML, DASHBOARD_CHARTS_CSS, DASHBOARD_CHARTS_JS
from .hostkey_trust import HostKeyError, preview_host_key, verify_and_stage

TEMPLATE = Environment(loader=BaseLoader(), autoescape=select_autoescape(default=True)).from_string('''
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · OSGate</title>
<style>
:root{color-scheme:dark;--bg:#10131b;--panel:#1b2030;--line:#363d50;--fg:#eef2fa;--soft:#a7b5cd;--accent:#7c9dff;--red:#f66;--green:#59d394}
@media(prefers-color-scheme:light){:root{color-scheme:light;--bg:#f6f7fa;--panel:white;--line:#d8deea;--fg:#182034;--soft:#525d76;--accent:#3455c5;--red:#b11;--green:#18794e}}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:15px system-ui,sans-serif;margin:0}header{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:14px 22px;background:var(--panel);border-bottom:1px solid var(--line)}header strong{font-size:20px;margin-right:12px}nav{display:flex;flex-wrap:wrap;gap:8px}a{color:var(--accent);text-decoration:none}nav a{padding:7px 10px;border-radius:6px}nav a:hover{background:var(--bg)}main{max-width:1280px;margin:24px auto;padding:0 16px}h1{font-size:26px}h2{font-size:18px}section,.card{padding:18px;margin:16px 0;border:1px solid var(--line);border-radius:12px;background:var(--panel)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px}.grid .card{margin:0}small,.muted{color:var(--soft)}table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}td,th{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}table{display:block;overflow-x:auto}input,select,button{background:var(--bg);color:var(--fg);padding:9px;border:1px solid var(--line);border-radius:6px;margin:3px;max-width:100%}button{background:var(--accent);color:white;border:0;cursor:pointer}button.danger{background:var(--red);color:#141414}.status{font-weight:700}.ONLINE{color:var(--green)}.OFFLINE{color:var(--red)}.DEGRADED,.CONNECTING,.RECONNECTING{color:#daa032}.inline{display:inline}.notice{color:var(--red)}label{display:inline-block;margin:5px 8px 5px 0}.stack label{display:block}form{margin:8px 0}input[type=number]{width:95px}input[type=checkbox]{width:auto}code{color:var(--accent)}
</style></head><body><header><strong>◈ OSGate</strong>{% if logged_in %}<nav>
<a href="/">Обзор</a><a href="/servers">SSH-серверы</a><a href="/clients">Клиенты</a><a href="/routing">Маршрутизация</a><a href="/route-history">История маршрутов</a><a href="/connections">Соединения</a><a href="/logs">Журнал</a><a href="/settings">Настройки</a></nav><form method="post" action="/logout" style="margin-left:auto"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Выход</button></form>{% endif %}</header>
<main><h1>{{ title }}</h1>{% if error %}<p class="notice">{{ error }}</p>{% endif %}{{ body | safe }}</main></body></html>''')


def page(request: Request, title: str, body: str, error=None):
    return HTMLResponse(TEMPLATE.render(title=title, body=body,
                        logged_in='admin' in request.session, csrf=csrf(request), error=error),
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


def csrf(request):
    if 'csrf' not in request.session:
        request.session['csrf'] = secrets.token_urlsafe(32)
    return request.session['csrf']


async def form_data(request):
    # Only urlencoded web forms; no file upload/unsanitized secrets handling.
    if 'application/x-www-form-urlencoded' not in request.headers.get('content-type', ''):
        raise HTTPException(415, 'Expected form-urlencoded')
    body = await request.body()
    if len(body) > 32768:
        raise HTTPException(413, 'Form too large')
    form = parse_qs(body.decode('utf-8'), keep_blank_values=True)
    return {key: values[-1] for key, values in form.items()}


def require_admin(request):
    if 'admin' not in request.session:
        raise HTTPException(401, 'Authentication required')
    if request.session.get('auth_generation') != request.app.state.runtime.db.auth_generation():
        raise HTTPException(401, 'Session expired')


def check_csrf(request, form):
    if not secrets.compare_digest(form.get('csrf', ''), request.session.get('csrf', '')):
        raise HTTPException(403, 'Invalid CSRF token')


def safe(v):
    return escape(str(v), quote=True)


def control(request):
    return f'<input type="hidden" name="csrf" value="{safe(csrf(request))}">'


def return_to(path):
    return RedirectResponse(path, status_code=303)


def esc_input(name, value='', typ='text', required=False, **other):
    more = ' '.join(f'{safe(k)}="{safe(v)}"' for k, v in other.items())
    return (f'<label>{safe(name)} <input type="{typ}" name="{safe(name)}" '
            f'value="{safe(value)}" {"required" if required else ""} {more}></label>')


def register_routes(app, runtime):
    db, ssh, socks, config = runtime.db, runtime.ssh, runtime.socks, runtime.settings

    @app.middleware('http')
    async def restrict_admin_ips(request, call_next):
        host = request.client.host if request.client else ''
        networks = [ipaddress.ip_network(x.strip()) for x in config.web_allowed_cidrs.split(',') if x.strip()]
        try:
            if not any(ipaddress.ip_address(host) in net for net in networks):
                return HTMLResponse('Forbidden', status_code=403)
        except ValueError:
            return HTMLResponse('Forbidden', status_code=403)
        return await call_next(request)

    @app.get('/healthz')
    async def healthz():
        return {'status': 'up', 'application': 'osgate'}

    @app.get('/login')
    async def login_form(request: Request):
        if (request.session.get('admin') and
                request.session.get('auth_generation') == db.auth_generation()):
            return return_to('/')
        request.session.clear()
        body = (f'<section><form method="post" action="/login" class="stack">{control(request)}'
                '<label>Логин <input name="username" required autocomplete="username"></label>'
                '<label>Пароль <input type="password" name="password" required autocomplete="current-password"></label>'
                '<button>Войти</button></form></section>')
        return page(request, 'Вход администратора', body)

    @app.post('/login')
    async def login(request: Request):
        data = await form_data(request)
        check_csrf(request, data)
        ip = request.client.host if request.client else 'unknown'
        now = asyncio.get_running_loop().time()
        attempts = app.state.login_attempts.setdefault(ip, [])
        attempts[:] = [t for t in attempts if now - t < 900]
        if len(attempts) >= 8:
            raise HTTPException(429, 'Слишком много попыток входа')
        if await asyncio.to_thread(db.verify_admin, data.get('username', ''), data.get('password', '')):
            request.session.clear()  # rotate session, prevent fixation
            request.session['admin'] = data['username']
            request.session['auth_generation'] = db.auth_generation()
            request.session['csrf'] = secrets.token_urlsafe(32)
            attempts.clear()
            await asyncio.to_thread(db.audit, data['username'], 'login', ip)
            return return_to('/')
        attempts.append(now)
        return page(request, 'Вход администратора', '<p>Неверный логин или пароль.</p><a href="/login">Повторить</a>', 'Ошибка авторизации')

    @app.post('/logout')
    async def logout(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        request.session.clear()
        return return_to('/login')

    @app.get('/')
    async def overview(request: Request):
        require_admin(request)
        servers = ssh.candidates()
        online = sum(s['ready'] for s in servers)
        up, down = await asyncio.to_thread(db.traffic_totals)
        uptime = max(0, int(asyncio.get_running_loop().time() - runtime.started_at))
        items = [('Состояние', 'ONLINE' if online else 'NO SSH'),
                 ('SOCKS5', 'RUNNING' if socks.server else 'STOPPED'),
                 ('SSH ONLINE', f'{online} / {len(servers)}'),
                 ('Активные соединения', len(socks.active)),
                 ('Завершено', socks.completed), ('Ошибки SOCKS', socks.rejected),
                 ('Клиентов онлайн', sum(count > 0 for count in socks.counts.values())),
                 ('Отправлено, байт', up + sum(t.uploaded for t in socks.active.values())),
                 ('Получено, байт', down + sum(t.downloaded for t in socks.active.values())),
                 ('Uptime, сек', uptime),
                 ('Последний failover', datetime.fromtimestamp(socks.router.last_failover, timezone.utc).strftime('%d.%m.%Y %H:%M:%S UTC') if socks.router.last_failover else '—')]
        body = '<div class="grid">' + ''.join(f'<div class="card"><small>{safe(k)}</small><h2>{safe(v)}</h2></div>' for k, v in items) + '</div>'
        body += '<style>' + DASHBOARD_CHARTS_CSS + '</style>' + DASHBOARD_CHARTS_HTML
        body += '<script>' + DASHBOARD_CHARTS_JS + '</script>'
        from .route_history_ui import history_table
        recent = await asyncio.to_thread(db.recent_route_events, limit=5)
        body += ('<section><h2>🔄 История переключений маршрутов</h2>'
                 '<p class="muted">Последние 5 событий · обновление каждые 5 секунд</p>')
        body += history_table(recent['events'], dom_id='dashboard-route-events')
        body += '<p><a href="/route-history">Вся история →</a></p></section>'
        from .route_history_ui import time_script
        body += time_script()
        body += '''<script>
        let lastRoutePreview='';
        async function refreshRoutePreview(){
          try{
            const response=await fetch('/api/route-events?limit=5',
              {cache:'no-store'});
            if(!response.ok)return;
            const data=await response.json();
            const signature=data.events.map(e=>e.id).join(',');
            if(signature===lastRoutePreview)return;
            lastRoutePreview=signature;
            const body=document.querySelector('#dashboard-route-events tbody');
            body.replaceChildren();
            const labels={
              offline:'🔴 SSH недоступен',
              forwarding_failed:'🔴 Ошибка TCP forwarding',
              recovered:'🟢 Восстановление',
              lower_rtt:'🟡 Меньшая задержка RTT',
              manual:'🔵 Ручной выбор',
              mode_changed:'🔵 Режим изменён',
              route_changed:'🔵 Маршрут изменён'};
            const modes={failover:'Failover',min_rtt:'Минимальный RTT',
              manual:'Ручной',round_robin:'Round Robin',
              weighted_round_robin:'Weighted Round Robin',sticky:'Sticky'};
            for(const event of data.events){
              const tr=document.createElement('tr');
              const when=document.createElement('td');
              when.textContent=new Date(event.time).toLocaleString('ru-RU');
              tr.appendChild(when);
              for(const content of [
                event.from_name|| (event.from_server_id? 'ID '+event.from_server_id:'—'),
                event.to_name|| (event.to_server_id?'ID '+event.to_server_id:'—'),
                labels[event.reason]||event.reason,
                modes[event.mode]||event.mode]){
                const td=document.createElement('td');td.textContent=content;
                tr.appendChild(td);
              }
              const td=document.createElement('td');
              const link=document.createElement('a');
              link.href='/route-history';link.textContent='Подробности';
              td.appendChild(link);tr.appendChild(td);body.appendChild(tr);
            }
            if(!data.events.length){
              const row=document.createElement('tr'),col=document.createElement('td');
              col.colSpan=6;col.textContent='Пока нет переключений';
              row.appendChild(col);body.appendChild(row);
            }
          }catch(_){}
        }
        refreshRoutePreview();setInterval(refreshRoutePreview,5000);
        </script>'''
        body += '<section><h2>Состояние SSH</h2><table id="ssh-status-table"><tr><th>Имя</th><th>Состояние</th><th>Каналы</th><th>Задержка</th></tr>'
        for s in servers:
            body += f'<tr><td>{safe(s["name"])}</td><td class="status {safe(s["status"])}">{safe(s["status"])}</td><td>{s["active_channels"]}</td><td>{safe(s["latency_ms"])} мс</td></tr>'
        body += """</table></section><section><a href="/metrics">Графики трафика</a></section>
<script>
async function updateDashboard(){try{
 const [a,b,c]=await Promise.all([fetch('/api/status',{cache:'no-store'}),fetch('/api/metrics',{cache:'no-store'}),fetch('/api/ssh-latency',{cache:'no-store'})]);
 if(!a.ok||!b.ok)return;
 const s=await a.json(),m=await b.json();
 renderDashboardTraffic(m);
 if(c.ok)renderDashboardLatency(s,await c.json());
 const values=[s.ssh_servers.some(x=>x.ready)?'ONLINE':'NO SSH',s.socks_running?'RUNNING':'STOPPED',
 s.ssh_servers.filter(x=>x.ready).length+' / '+s.ssh_servers.length,
 s.active_connections,s.completed_connections,s.rejected_connections,s.active_clients,
 m.uploaded,m.downloaded,s.uptime_seconds,s.last_failover?new Date(s.last_failover*1000).toLocaleString('ru-RU'):'—'];
 document.querySelectorAll('.grid .card h2').forEach((x,i)=>{if(i<values.length)x.textContent=values[i]});
 const rows=document.getElementById('ssh-status-table').querySelectorAll('tr');
 s.ssh_servers.forEach((x,i)=>{if(!rows[i+1])return;
 const cells=rows[i+1].querySelectorAll('td');if(cells.length<4)return;
 cells[1].textContent=x.status;cells[1].className='status '+x.status;
 cells[2].textContent=x.active_channels;cells[3].textContent=x.latency_ms??'—';});
}catch(_){}}
updateDashboard();setInterval(updateDashboard,5000);
</script>"""
        return page(request, 'Панель управления', body)

    @app.get('/servers')
    async def server_list(request: Request):
        require_admin(request)
        states = {x['id']: x for x in ssh.candidates()}
        rows = '<section><table><tr><th>Имя</th><th>Хост</th><th>Приоритет</th><th>Вес</th><th>Состояние</th><th>Действия</th></tr>'
        for rec in await asyncio.to_thread(db.servers):
            state = states.get(rec['id'], {})
            rows += f'<tr><td>{safe(rec["name"])}</td><td>{safe(rec["host"])}:{rec["port"]}</td><td>{rec["priority"]}</td><td>{rec["weight"]}</td><td class="status {safe(state.get("status", "DISABLED"))}">{safe(state.get("status", "DISABLED"))}</td>'
            rows += (f'<td><a href="/servers/{rec["id"]}/edit">Изменить / проверить</a> · '
                     f'<a href="/servers/{rec["id"]}/onboard">Настроить SSH-доступ</a> '
                     f'<form class="inline" method="post" action="/servers/{rec["id"]}/toggle">{control(request)}<button>{"Отключить" if rec["enabled"] else "Включить"}</button></form>'
                     f'<form class="inline" method="post" action="/servers/{rec["id"]}/delete">{control(request)}<button class="danger">Удалить</button></form></td></tr>')
        rows += '</table></section><section><h2>Добавить SSH-сервер</h2><p class="muted">Ключ и known_hosts сначала разместите в защищённом SSH_DIRECTORY. Fingerprint должен быть подтверждён отдельно.</p>'
        rows += ('<p>Если сервер ещё не принимает ключ OSGate, '
                 'отметьте «Настроить SSH-доступ через пароль при добавлении». '
                 'После установки публичного ключа будет выполнена обычная '
                 'проверка SSH/TCP forwarding. Потребуется разрешённый '
                 'парольный вход на удалённом сервере.</p>')
        rows += f'<form method="post" action="/servers/new">{control(request)}'
        for name, value, typ in [('name','','text'),('host','','text'),('port',22,'number'),('username','','text'),('key_file','/ssh/id_ed25519','text'),('known_hosts_file','/ssh/known_hosts','text'),('priority',100,'number'),('weight',1,'number')]:
            rows += esc_input(name, value, typ, True)
        rows += ('<section><h3>Подлинность SSH-сервера</h3>'
                 '<p>Если сервер ещё не содержится в known_hosts, сначала '
                 'получите его SHA256-отпечаток. Сверьте его с отпечатком '
                 'на консоли сервера или через другой доверенный канал. '
                 'Это не автоматическое доверие!</p>'
                 '<button type="button" id="hostkey-preview">'
                 'Показать SHA256-отпечаток</button>'
                 '<p id="hostkey-result"></p>'
                 '<label>Подтверждённый SHA256 fingerprint '
                 '<input name="verified_fingerprint" type="text" '
                 'autocomplete="off" size="58" placeholder="SHA256:..."></label>'
                 '<label><input name="confirm_hostkey" type="checkbox" value="yes">'
                 'Сверил fingerprint через независимый доверенный канал '
                 'и разрешаю сохранить ключ сервера</label></section>')
        rows += ('''<script>
        document.getElementById('hostkey-preview').onclick=async function(){
          const form=this.closest('form'), msg=document.getElementById('hostkey-result');
          msg.textContent='Получение ключа (он пока НЕ доверен)...';
          try {
            const params=new URLSearchParams();
            params.set('csrf',form.querySelector('[name=csrf]').value);
            params.set('host',form.querySelector('[name=host]').value);
            params.set('port',form.querySelector('[name=port]').value);
            const response=await fetch('/api/ssh/hostkey-preview',{
              method:'POST',body:params,headers:{'Content-Type':'application/x-www-form-urlencoded'}});
            if(!response.ok){msg.textContent='Не удалось получить ключ. Проверьте host и порт.';return}
            const data=await response.json();
            msg.textContent='НЕПРОВЕРЕННЫЙ SHA256: '+data.fingerprint
               +' — сверить независимо и вручную ввести в поле подтверждения.';
          } catch(_){msg.textContent='Ошибка запроса SSH host key.'}
        };
        </script>''')
        rows += ('<label><input type="checkbox" name="install_key" value="yes">'
                 'Настроить SSH-доступ через пароль при добавлении</label>')
        rows += ('<label>Пароль SSH (только для первоначальной настройки) '
                 '<input type="password" name="ssh_password" autocomplete="off"></label>')
        rows += ('<p class="muted">Пароль используется однократно и не хранится. '
                 'Публичный ключ устанавливается только на сервер с заранее '
                 'проверенным known_hosts.</p>')
        rows += '<button>Добавить</button></form></section>'
        return page(request, 'SSH-серверы', rows)

    @app.post('/api/ssh/hostkey-preview')
    async def hostkey_preview_api(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        try:
            host = data.get('host', '')
            port = int(data.get('port', '22'))
            _, fingerprint = await preview_host_key(
                host, port, config.ssh_connect_timeout)
        except (ValueError, HostKeyError) as exc:
            raise HTTPException(400, 'Не удалось получить SSH host key') from exc
        return JSONResponse({'fingerprint': fingerprint},
                            headers={'Cache-Control': 'no-store'})

    @app.post('/servers/new')
    async def new_server(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        staged = None
        persisted = False
        try:
            record = dict(name=data['name'].strip()[:120], host=data['host'].strip()[:255],
                          port=int(data['port']), username=data['username'].strip()[:120],
                          key_file=data['key_file'], known_hosts_file=data['known_hosts_file'],
                          priority=int(data.get('priority', 100)), weight=int(data.get('weight', 1)))
            if not (record['name'] and record['host'] and record['username'] and
                    1 <= record['port'] <= 65535 and 1 <= record['weight'] <= 1000):
                raise ValueError('Invalid fields')
            # One-time trust is accepted ONLY when fingerprint was checked
            # against an independent trusted source and entered explicitly.
            if data.get('confirm_hostkey') == 'yes':
                staged = await verify_and_stage(
                    record['host'], record['port'],
                    data.get('verified_fingerprint', ''), config)
                record['known_hosts_file'] = str(staged)
            elif data.get('verified_fingerprint'):
                raise HTTPException(400, 'Требуется подтверждение SSH host key.')
            # Optional one-time enrollment precedes normal SSH/TCP forwarding
            # verification and never persists the supplied SSH password.
            if data.get('install_key') == 'yes':
                from .ssh_onboarding import enroll_public_key
                key = (request.session['admin'], 'new')
                attempts = app.state.ssh_enrollment_attempts
                recent = attempts.setdefault(key, [])
                now = asyncio.get_running_loop().time()
                recent[:] = [t for t in recent if now - t < 900]
                if len(recent) >= 5:
                    raise HTTPException(429, 'Слишком много попыток SSH. Повторите позже.')
                recent.append(now)
                await enroll_public_key(record, config, data.get('ssh_password', ''))
            conn = await asyncio.wait_for(connect_ssh(record, config), timeout=config.ssh_connect_timeout + 2)
            try:
                reader, writer = await asyncio.wait_for(
                    conn.open_connection(config.health_test_host, config.health_test_port),
                    timeout=config.health_check_timeout)
                writer.close()
            finally:
                conn.close()
                await conn.wait_closed()
            with db.session() as s:
                s.add(SSHServer(**record))
            persisted = True  # After commit, the trusted hostkey path must remain valid.
            await asyncio.to_thread(db.audit, request.session['admin'], 'server_add', record['name'])
            await ssh.refresh()
        except HTTPException:
            if staged is not None and not persisted:
                staged.unlink(missing_ok=True)
            raise
        except Exception as exc:
            if staged is not None and not persisted:
                staged.unlink(missing_ok=True)
            from .ssh_onboarding import EnrollmentError
            if isinstance(exc, EnrollmentError):
                reason = safe(str(exc))
            else:
                reason = safe(type(exc).__name__)
            return page(request, 'Ошибка добавления сервера',
                        '<p>Конфигурация не сохранена.</p>'
                        '<p>При HostKeyNotVerifiable используйте кнопку '
                        '«Показать SHA256-отпечаток» и подтвердите его '
                        'после независимой проверки.</p>'
                        '<a href="/servers">Назад</a>',
                        reason)
        return return_to('/servers')

    @app.post('/servers/{server_id}/toggle')
    async def toggle_server(request: Request, server_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as s:
            record = s.get(SSHServer, server_id)
            if not record:
                raise HTTPException(404)
            record.enabled = not record.enabled
        await asyncio.to_thread(db.audit, request.session['admin'], 'server_toggle', str(server_id))
        await ssh.refresh()
        return return_to('/servers')

    @app.post('/servers/{server_id}/delete')
    async def delete_server(request: Request, server_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as s:
            record = s.get(SSHServer, server_id)
            if record:
                for user in s.scalars(select(Client).where(Client.pinned_server_id == server_id)):
                    user.pinned_server_id = None
                s.delete(record)
        await asyncio.to_thread(db.audit, request.session['admin'], 'server_delete', str(server_id))
        await ssh.refresh()
        return return_to('/servers')

    @app.get('/clients')
    async def client_list(request: Request):
        require_admin(request)
        with db.session() as s:
            users = list(s.scalars(select(Client).order_by(Client.id)))
            rows = '<section><table><tr><th>Имя</th><th>Логин</th><th>Статус</th><th>Соединения</th><th>Трафик, байт ↑ / ↓</th><th>Действия</th></tr>'
            for x in users:
                rows += (f'<tr><td>{safe(x.name)}</td><td>{safe(x.username)}</td><td>{"ACTIVE" if x.enabled else "BLOCKED"}</td>'
                         f'<td>{socks.counts.get(x.id,0)} / {x.max_connections}</td><td>{x.bytes_uploaded} / {x.bytes_downloaded}</td><td>'
                         f'<a href="/clients/{x.id}/edit">Редактировать / пароль</a> '
                         f'<form class="inline" method="post" action="/clients/{x.id}/toggle">{control(request)}<button>{"Заблокировать" if x.enabled else "Разблокировать"}</button></form>'
                         f'<form class="inline" method="post" action="/clients/{x.id}/delete">{control(request)}<button class="danger">Удалить</button></form></td></tr>')
        rows += '</table></section><section><h2>Новый SOCKS5-клиент</h2>'
        rows += f'<form method="post" action="/clients/new">{control(request)}'
        for name, value, typ in [('name','','text'),('username','','text'),('password','','password'),('max_connections',100,'number'),('pinned_server_id','','number')]:
            rows += esc_input(name, value, typ, name not in ('pinned_server_id',))
        rows += '<label><input type="checkbox" name="allow_fallback" value="yes">Разрешить резервный сервер</label><button>Создать</button></form></section>'
        return page(request, 'SOCKS5-клиенты', rows)

    @app.post('/clients/new')
    async def create_client(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        if len(data.get('password', '')) < 12 or not data.get('username') or not data.get('name'):
            raise HTTPException(400, 'Password min 12 characters')
        pinned = int(data['pinned_server_id']) if data.get('pinned_server_id') else None
        with db.session() as s:
            if pinned and not s.get(SSHServer, pinned):
                raise HTTPException(400, 'Unknown SSH server')
            s.add(Client(name=data['name'][:120], username=data['username'][:120],
                         password_hash=hasher.hash(data['password']),
                         max_connections=max(1, min(int(data['max_connections']), 10000)),
                         pinned_server_id=pinned, allow_fallback=data.get('allow_fallback') == 'yes'))
        await asyncio.to_thread(db.audit, request.session['admin'], 'client_add', data['username'][:120])
        return return_to('/clients')

    @app.post('/clients/{client_id}/toggle')
    async def toggle_client(request: Request, client_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as s:
            user = s.get(Client, client_id)
            if not user: raise HTTPException(404)
            user.enabled = not user.enabled
        if not user.enabled:
            for tunnel in list(socks.active.values()):
                if tunnel.client_id == client_id:
                    await socks.disconnect(tunnel.id)
        await asyncio.to_thread(db.audit, request.session['admin'], 'client_toggle', str(client_id))
        return return_to('/clients')

    @app.post('/clients/{client_id}/delete')
    async def delete_client(request: Request, client_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as s:
            user = s.get(Client, client_id)
            if user: s.delete(user)
        await asyncio.to_thread(db.audit, request.session['admin'], 'client_delete', str(client_id))
        return return_to('/clients')

    @app.get('/routing')
    async def routing_page(request: Request):
        require_admin(request)
        settings = await asyncio.to_thread(db.routing)
        body = f'<section><form method="post" action="/routing">{control(request)}'
        body += '<label>Режим <select name="mode">'
        labels = {
            'failover': 'Резервирование (по приоритету)',
            'round_robin': 'По очереди (Round Robin)',
            'weighted_round_robin': 'По весам (Weighted Round Robin)',
            'manual': 'Вручную',
            'sticky': 'Закрепление за клиентом (Sticky)',
            'min_rtt': 'Минимальная задержка (RTT)',
        }
        for m in sorted(MODES):
            body += (f'<option value="{m}" '
                     f'{"selected" if m == settings["mode"] else ""}>'
                     f'{safe(labels[m])}</option>')
        body += ('<p class="muted">Минимальная задержка (RTT): новые SOCKS5-'
                 'соединения идут через доступный сервер с наименьшим '
                 'временем TCP-проверки через SSH. При отказе пробуется '
                 'следующий сервер; существующие соединения не переносятся. '
                 'Привязка клиента к SSH-серверу имеет приоритет.</p>')
        body += '</select></label>' + esc_input('manual_server_id', settings['manual_server_id'] or '', 'number')
        body += '<label><input type="checkbox" name="auto_failback" value="yes"' + (' checked' if settings['auto_failback'] else '') + '>Автовозврат основного сервера</label><button>Применить</button></form></section>'
        return page(request, 'Маршрутизация', body)

    @app.post('/routing')
    async def change_routing(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        if data.get('mode') not in MODES:
            raise HTTPException(400, 'Unsupported routing mode')
        mid = int(data['manual_server_id']) if data.get('manual_server_id') else None
        try:
            delay = float(data.get('failback_delay', '60'))
            if not 0 <= delay <= 3600:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(400, 'Invalid failback delay') from exc
        before = await asyncio.to_thread(db.routing)
        with db.session() as s:
            if data['mode'] == 'manual' and (not mid or not s.get(SSHServer, mid)):
                raise HTTPException(400, 'Manual SSH server required')
            route = s.get(Routing, 1)
            route.mode = data['mode']
            route.manual_server_id = mid
            route.auto_failback = data.get('auto_failback') == 'yes'
        await asyncio.to_thread(db.set_setting, 'failback_delay', str(delay))
        if (before['mode'] != data['mode']
                or (data['mode'] == 'manual'
                    and before['manual_server_id'] != mid)):
            await asyncio.to_thread(
                db.record_route_event,
                from_server_id=before['manual_server_id'] if before['mode'] == 'manual' else None,
                to_server_id=mid if data['mode'] == 'manual' else None,
                reason='mode_changed', mode=data['mode'],
                actor=request.session['admin'],
                details={'old_mode': before['mode'], 'new_mode': data['mode']})
            socks.route_tracker.reset()
        await asyncio.to_thread(db.audit, request.session['admin'], 'routing_change', data['mode'])
        return return_to('/routing')

    @app.get('/connections')
    async def connections(request: Request):
        require_admin(request)
        body = '<section><table><tr><th>Клиент</th><th>Назначение</th><th>SSH ID</th><th>Отправлено</th><th>Получено</th><th>Действие</th></tr>'
        for tunnel in list(socks.active.values()):
            body += (f'<tr><td>{safe(tunnel.username)}</td><td>{safe(tunnel.destination)}:{tunnel.port}</td><td>{tunnel.ssh_server_id}</td>'
                     f'<td>{tunnel.uploaded}</td><td>{tunnel.downloaded}</td><td><form method="post" action="/connections/{tunnel.id}/close">{control(request)}<button class="danger">Отключить</button></form></td></tr>')
        return page(request, 'Активные соединения', body + '</table></section><script>setTimeout(()=>location.reload(),15000)</script>')

    @app.post('/connections/{tunnel_id}/close')
    async def close_connection(request: Request, tunnel_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        await socks.disconnect(tunnel_id)
        await asyncio.to_thread(db.audit, request.session['admin'], 'disconnect', str(tunnel_id))
        return return_to('/connections')

    @app.get('/logs')
    async def logs(request: Request):
        require_admin(request)
        with db.session() as s:
            recent = list(s.scalars(select(Event).order_by(desc(Event.id)).limit(100)))
            audits = list(s.scalars(select(Audit).order_by(desc(Audit.id)).limit(50)))
        body = '<section><h2>События SSH / система</h2><table><tr><th>Время UTC</th><th>Тип</th><th>Событие</th></tr>'
        for x in recent:
            body += f'<tr><td>{safe(x.when)}</td><td>{safe(x.category)}</td><td>{safe(x.message)}</td></tr>'
        body += '</table></section><section><h2>Аудит администратора</h2><table>'
        for x in audits:
            body += f'<tr><td>{safe(x.when)}</td><td>{safe(x.actor)}</td><td>{safe(x.action)}</td><td>{safe(x.detail)}</td></tr>'
        body += '</table></section><section><a href="/api/diagnostics">Диагностика JSON</a> · <a href="/api/events.csv">Экспорт CSV</a></section>'
        return page(request, 'Журнал событий', body)

    @app.get('/settings')
    async def settings_page(request: Request):
        require_admin(request)
        body = ('<section><h2>Сетевые настройки (из .env)</h2><p>Для изменения слушающих интерфейсов необходим перезапуск.</p>'
                f'<p>Web: <code>{safe(config.web_host)}:{config.web_port}</code></p>'
                f'<p>SOCKS5: <code>{safe(config.socks_host)}:{config.socks_port}</code></p>'
                f'<p>Проверка SSH каждые {config.health_check_interval} с</p>'
                '<p>Чувствительные параметры не отображаются.</p></section>')
        body += '<section><a href="/admin/password">Смена пароля администратора</a> · <a href="/settings/runtime">Параметры работы</a> · <a href="/metrics">Графики</a></section>'
        return page(request, 'Настройки', body)

    @app.get('/api/ssh-latency')
    async def api_ssh_latency(request: Request):
        require_admin(request)
        samples = await asyncio.to_thread(db.recent_ssh_latency)
        return JSONResponse({'window_seconds': 600, 'samples': samples},
                            headers={'Cache-Control': 'no-store'})

    @app.get('/api/status')
    async def api_status(request: Request):
        require_admin(request)
        public = ('id', 'name', 'status', 'ready', 'active_channels', 'latency_ms',
                  'reconnect_count', 'last_error')
        return JSONResponse({
            'ssh_servers': [{k: item[k] for k in public} for item in ssh.candidates()],
            'active_connections': len(socks.active),
            'active_clients': sum(count > 0 for count in socks.counts.values()),
            'uptime_seconds': max(0, int(asyncio.get_running_loop().time() - runtime.started_at)),
            'last_failover': socks.router.last_failover,
            'socks_running': socks.server is not None,
            'completed_connections': socks.completed,
            'rejected_connections': socks.rejected,
        }, headers={'Cache-Control': 'no-store'})

    from .web_v1 import register_v1_routes
    register_v1_routes(app, runtime)
    from .route_history_ui import register_route_history_routes
    register_route_history_routes(app, runtime)
