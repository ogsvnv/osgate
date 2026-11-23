"""Russian-language administrative UI with separate authorization and CSRF checks."""
import asyncio
import ipaddress
import secrets
from datetime import datetime
from html import escape
from urllib.parse import parse_qs

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from jinja2 import Environment, BaseLoader, select_autoescape
from sqlalchemy import select, desc

from .database import Admin, Client, SSHServer, Routing, Event, Audit, hasher
from .routing import MODES
from .ssh import connect_ssh

TEMPLATE = Environment(loader=BaseLoader(), autoescape=select_autoescape(default=True)).from_string('''
<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} · OSGate</title>
<style>
:root{color-scheme:dark;--bg:#10131b;--panel:#1b2030;--line:#363d50;--fg:#eef2fa;--soft:#a7b5cd;--accent:#7c9dff;--red:#f66;--green:#59d394}
@media(prefers-color-scheme:light){:root{color-scheme:light;--bg:#f6f7fa;--panel:white;--line:#d8deea;--fg:#182034;--soft:#525d76;--accent:#3455c5;--red:#b11;--green:#18794e}}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:15px system-ui,sans-serif;margin:0}header{display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:14px 22px;background:var(--panel);border-bottom:1px solid var(--line)}header strong{font-size:20px;margin-right:12px}nav{display:flex;flex-wrap:wrap;gap:8px}a{color:var(--accent);text-decoration:none}nav a{padding:7px 10px;border-radius:6px}nav a:hover{background:var(--bg)}main{max-width:1280px;margin:24px auto;padding:0 16px}h1{font-size:26px}h2{font-size:18px}section,.card{padding:18px;margin:16px 0;border:1px solid var(--line);border-radius:12px;background:var(--panel)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:12px}.grid .card{margin:0}small,.muted{color:var(--soft)}table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}td,th{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}table{display:block;overflow-x:auto}input,select,button{background:var(--bg);color:var(--fg);padding:9px;border:1px solid var(--line);border-radius:6px;margin:3px;max-width:100%}button{background:var(--accent);color:white;border:0;cursor:pointer}button.danger{background:var(--red);color:#141414}.status{font-weight:700}.ONLINE{color:var(--green)}.OFFLINE{color:var(--red)}.DEGRADED,.CONNECTING,.RECONNECTING{color:#daa032}.inline{display:inline}.notice{color:var(--red)}label{display:inline-block;margin:5px 8px 5px 0}.stack label{display:block}form{margin:8px 0}input[type=number]{width:95px}input[type=checkbox]{width:auto}code{color:var(--accent)}
</style></head><body><header><strong>◈ OSGate</strong>{% if logged_in %}<nav>
<a href="/">Обзор</a><a href="/servers">SSH-серверы</a><a href="/clients">Клиенты</a><a href="/routing">Маршрутизация</a><a href="/connections">Соединения</a><a href="/logs">Журнал</a><a href="/settings">Настройки</a></nav><form method="post" action="/logout" style="margin-left:auto"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Выход</button></form>{% endif %}</header>
<main><h1>{{ title }}</h1>{% if error %}<p class="notice">{{ error }}</p>{% endif %}{{ body | safe }}</main></body></html>''')


def page(request: Request, title: str, body: str, error=None):
    return HTMLResponse(TEMPLATE.render(title=title, body=body, logged_in='admin' in request.session,
                        csrf=csrf(request), error=error))


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
        if request.session.get('admin'):
            return return_to('/')
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
        items = [('Состояние', 'ONLINE' if online else 'NO SSH'),
                 ('SOCKS5', 'RUNNING' if socks.server else 'STOPPED'),
                 ('SSH ONLINE', f'{online} / {len(servers)}'),
                 ('Активные соединения', len(socks.active)),
                 ('Завершено', socks.completed), ('Ошибки SOCKS', socks.rejected)]
        body = '<div class="grid">' + ''.join(f'<div class="card"><small>{safe(k)}</small><h2>{safe(v)}</h2></div>' for k, v in items) + '</div>'
        body += '<section><h2>Состояние SSH</h2><table><tr><th>Имя</th><th>Состояние</th><th>Каналы</th><th>Задержка</th></tr>'
        for s in servers:
            body += f'<tr><td>{safe(s["name"])}</td><td class="status {safe(s["status"])}">{safe(s["status"])}</td><td>{s["active_channels"]}</td><td>{safe(s["latency_ms"])} мс</td></tr>'
        return page(request, 'Панель управления', body + '</table></section><script>setTimeout(()=>location.reload(),15000)</script>')

    @app.get('/servers')
    async def server_list(request: Request):
        require_admin(request)
        states = {x['id']: x for x in ssh.candidates()}
        rows = '<section><table><tr><th>Имя</th><th>Хост</th><th>Приоритет</th><th>Вес</th><th>Состояние</th><th>Действия</th></tr>'
        for rec in await asyncio.to_thread(db.servers):
            state = states.get(rec['id'], {})
            rows += f'<tr><td>{safe(rec["name"])}</td><td>{safe(rec["host"])}:{rec["port"]}</td><td>{rec["priority"]}</td><td>{rec["weight"]}</td><td class="status {safe(state.get("status", "DISABLED"))}">{safe(state.get("status", "DISABLED"))}</td>'
            rows += (f'<td><form class="inline" method="post" action="/servers/{rec["id"]}/toggle">{control(request)}<button>{"Отключить" if rec["enabled"] else "Включить"}</button></form>'
                     f'<form class="inline" method="post" action="/servers/{rec["id"]}/delete">{control(request)}<button class="danger">Удалить</button></form></td></tr>')
        rows += '</table></section><section><h2>Добавить SSH-сервер</h2><p class="muted">Ключ и known_hosts сначала разместите в защищённом SSH_DIRECTORY. Fingerprint должен быть подтверждён отдельно.</p>'
        rows += f'<form method="post" action="/servers/new">{control(request)}'
        for name, value, typ in [('name','','text'),('host','','text'),('port',22,'number'),('username','','text'),('key_file','/ssh/id_ed25519','text'),('known_hosts_file','/ssh/known_hosts','text'),('priority',100,'number'),('weight',1,'number')]:
            rows += esc_input(name, value, typ, True)
        rows += '<button>Добавить</button></form></section>'
        return page(request, 'SSH-серверы', rows)

    @app.post('/servers/new')
    async def new_server(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        try:
            record = dict(name=data['name'].strip()[:120], host=data['host'].strip()[:255],
                          port=int(data['port']), username=data['username'].strip()[:120],
                          key_file=data['key_file'], known_hosts_file=data['known_hosts_file'],
                          priority=int(data.get('priority', 100)), weight=int(data.get('weight', 1)))
            if not (record['name'] and record['host'] and record['username'] and
                    1 <= record['port'] <= 65535 and 1 <= record['weight'] <= 1000):
                raise ValueError('Invalid fields')
            # Confirm SSH transport and TCP forwarding before saving configuration.
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
            await asyncio.to_thread(db.audit, request.session['admin'], 'server_add', record['name'])
            await ssh.refresh()
        except Exception as exc:
            return page(request, 'Ошибка добавления сервера', '<p>Конфигурация не сохранена.</p><a href="/servers">Назад</a>', type(exc).__name__)
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
        for m in sorted(MODES):
            body += f'<option value="{m}" {"selected" if m == settings["mode"] else ""}>{m}</option>'
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
        with db.session() as s:
            if data['mode'] == 'manual' and (not mid or not s.get(SSHServer, mid)):
                raise HTTPException(400, 'Manual SSH server required')
            route = s.get(Routing, 1)
            route.mode = data['mode']
            route.manual_server_id = mid
            route.auto_failback = data.get('auto_failback') == 'yes'
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
        return page(request, 'Журнал событий', body + '</table></section>')

    @app.get('/settings')
    async def settings_page(request: Request):
        require_admin(request)
        body = ('<section><h2>Сетевые настройки (из .env)</h2><p>Для изменения слушающих интерфейсов необходим перезапуск.</p>'
                f'<p>Web: <code>{safe(config.web_host)}:{config.web_port}</code></p>'
                f'<p>SOCKS5: <code>{safe(config.socks_host)}:{config.socks_port}</code></p>'
                f'<p>Проверка SSH каждые {config.health_check_interval} с</p>'
                '<p>Чувствительные параметры не отображаются.</p></section>')
        return page(request, 'Настройки', body)

    @app.get('/api/status')
    async def api_status(request: Request):
        require_admin(request)
        return {'ssh_servers': ssh.candidates(), 'active_connections': len(socks.active),
                'socks_running': socks.server is not None,
                'completed_connections': socks.completed, 'rejected_connections': socks.rejected}
