"""Authenticated administrative controls for SSH routes and SOCKS5 users."""
import asyncio
import csv
import io
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from .database import Admin, Client, SSHServer, Event, hasher
from .ssh import connect_ssh
from .hostkey_trust import HostKeyError, preview_host_key, verify_and_stage
from .ssh_onboarding import EnrollmentError, enroll_public_key
from .web import check_csrf, control, esc_input, form_data, page, require_admin, return_to, safe


def parse_server_form(data):
    try:
        fields = {'name': data['name'].strip()[:120],
                  'host': data['host'].strip()[:255],
                  'username': data['username'].strip()[:120],
                  'port': int(data['port']),
                  'priority': int(data['priority']),
                  'weight': int(data['weight']),
                  'key_file': data['key_file'].strip(),
                  'known_hosts_file': data['known_hosts_file'].strip()}
        if not all(fields[k] for k in ('name', 'host', 'username', 'key_file', 'known_hosts_file')):
            raise ValueError
        if not 1 <= fields['port'] <= 65535 or not 1 <= fields['weight'] <= 1000:
            raise ValueError
        return fields
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(400, 'Invalid SSH server settings') from exc


async def probe_ssh(record, settings):
    conn = await asyncio.wait_for(connect_ssh(record, settings), timeout=settings.ssh_connect_timeout + 2)
    try:
        _, writer = await asyncio.wait_for(
            conn.open_connection(settings.health_test_host, settings.health_test_port),
            timeout=settings.health_check_timeout)
        writer.close()
    finally:
        conn.close()
        await conn.wait_closed()


def register_v1_routes(app, runtime):
    db, ssh, socks, cfg = runtime.db, runtime.ssh, runtime.socks, runtime.settings

    @app.get('/servers/{server_id}/edit')
    async def server_edit_form(request: Request, server_id: int):
        require_admin(request)
        with db.session() as session:
            server = session.get(SSHServer, server_id)
            if not server:
                raise HTTPException(404)
            values = {name: getattr(server, name) for name in (
                'name', 'host', 'username', 'port', 'priority', 'weight',
                'key_file', 'known_hosts_file')}
        body = '<section><form method="post" action="/servers/%d/edit">' % server_id + control(request)
        for key, value in values.items():
            body += esc_input(key, value, 'number' if key in ('port', 'priority', 'weight') else 'text', True)
        body += '<p>Перед сохранением проверяется SSH и TCP forwarding.</p><button>Проверить и сохранить</button></form></section>'
        body += '<section>'
        for action, title in (('check', 'Проверить подключение'),
                              ('reconnect', 'Переподключить'),
                              ('primary', 'Сделать основным')):
            body += '<form method="post" action="/servers/%d/%s">%s<button>%s</button></form>' % (
                server_id, action, control(request), title)
        body += (f'<p><a href="/servers/{server_id}/hostkey">'
                 'Проверить и подтвердить ключ SSH-сервера</a> · '
                 f'<a href="/servers/{server_id}/onboard">'
                 'Настроить SSH-доступ (установить публичный ключ)</a></p>')
        return page(request, 'SSH-сервер — редактирование', body + '</section>')

    @app.get('/servers/{server_id}/hostkey')
    async def server_hostkey_preview(request: Request, server_id: int):
        require_admin(request)
        with db.session() as session:
            item = session.get(SSHServer, server_id)
            if item is None:
                raise HTTPException(404)
            record = {k: getattr(item, k) for k in (
                'name', 'host', 'port', 'username', 'known_hosts_file')}
        try:
            _, fingerprint = await preview_host_key(
                record['host'], record['port'], cfg.ssh_connect_timeout)
        except HostKeyError as exc:
            return page(request, 'SSH host key: проверка недоступна',
                        '<section><p>' + safe(exc) + '</p></section>')
        body = ('<section><h2>Непроверенный ключ SSH-сервера</h2>'
                '<p>Ключ получен по сети и ПОКА НЕ ЯВЛЯЕТСЯ ДОВЕРЕННЫМ. '
                'Сверьте отпечаток с консолью SSH-сервера или другим '
                'доверенным каналом. Не подтверждайте ключ, только потому '
                'что он показан на этой странице.</p>')
        body += (f'<p>Сервер: <b>{safe(record["name"])}</b>, '
                 f'{safe(record["host"])}:{record["port"]}</p>')
        body += '<p>SHA256 fingerprint: <code>' + safe(fingerprint) + '</code></p>'
        body += ('<p>После независимой проверки введите ТОЧНО такой же '
                 'отпечаток для разрешения подключения.</p>')
        body += f'<form method="post" action="/servers/{server_id}/hostkey">'
        body += control(request)
        body += ('<label>Подтверждённый SHA256-отпечаток '
                 '<input type="text" name="verified_fingerprint" '
                 'autocomplete="off" required size="58"></label>')
        body += ('<label><input type="checkbox" name="confirmed" value="yes" '
                 'required>Сверил отпечаток через доверенный канал и '
                 'разрешаю доверять этому SSH-серверу</label>')
        body += '<button>Принять ключ и проверить подключение</button></form></section>'
        return page(request, 'Проверка ключа SSH-сервера', body)

    @app.post('/servers/{server_id}/hostkey')
    async def server_hostkey_accept(request: Request, server_id: int):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        if data.get('confirmed') != 'yes':
            raise HTTPException(400, 'Подтвердите независимую проверку отпечатка.')
        with db.session() as session:
            item = session.get(SSHServer, server_id)
            if item is None:
                raise HTTPException(404)
            record = {k: getattr(item, k) for k in (
                'host', 'port', 'name', 'username', 'key_file', 'known_hosts_file')}
        try:
            trust = await verify_and_stage(
                record['host'], record['port'],
                data.get('verified_fingerprint', ''), cfg)
        except HostKeyError as exc:
            return page(request, 'SSH host key не принят',
                        '<section><p>' + safe(exc) +
                        '</p><a href="/servers">Назад</a></section>')
        try:
            record['known_hosts_file'] = str(trust)
            with db.session() as session:
                item = session.get(SSHServer, server_id)
                if (item is None or item.host != record['host']
                        or item.port != record['port']):
                    raise HTTPException(409, 'Настройки сервера изменились. Повторите проверку.')
                item.known_hosts_file = str(trust)
        except Exception:
            trust.unlink(missing_ok=True)
            raise
        await asyncio.to_thread(db.audit, request.session['admin'],
                                'ssh_hostkey_approved', str(server_id))
        await ssh.refresh()
        try:
            await probe_ssh(record, cfg)
        except Exception as exc:
            # The host key is trusted, but authentication or TCP forwarding
            # may still fail independently. Do not roll back independent trust.
            return page(request, 'Ключ SSH-сервера подтверждён',
                        '<section><p>Host key сохранён, но SSH или TCP '
                        'forwarding ещё не работают: ' + safe(type(exc).__name__) +
                        '.</p><p>Проверьте авторизацию SSH-пользователя.</p>'
                        f'<a href="/servers/{server_id}/onboard">'
                        'Установить публичный ключ пользователя</a></section>')
        return page(request, 'Ключ SSH-сервера подтверждён',
                    '<section><p>Host key сохранён. SSH и TCP forwarding '
                    'успешно проверены.</p><a href="/servers">К серверам</a></section>')

    @app.get('/servers/{server_id}/onboard')
    async def server_onboarding_form(request: Request, server_id: int):
        require_admin(request)
        with db.session() as session:
            server = session.get(SSHServer, server_id)
            if server is None:
                raise HTTPException(404)
            host, port, username, name = server.host, server.port, server.username, server.name
        body = '<section><h2>Настроить SSH-доступ</h2>'
        body += ('<p>OSGate установит публичную часть своего SSH-ключа в '
                 '<code>~/.ssh/authorized_keys</code> выбранного пользователя.</p>')
        body += (f'<p>Сервер: <strong>{safe(name)}</strong>, '
                 f'<code>{safe(username)}@{safe(host)}:{port}</code></p>')
        body += ('<p>Используется только пароль SSH, подтверждённый host key '
                 'из существующего файла known_hosts. Пароль не сохраняется '
                 'в базе и не выводится в журнал.</p>')
        body += ('<p>Если сервер запрещает PasswordAuthentication, '
                 'понадобится уже разрешённый SSH-ключ или настройка администратором.</p>')
        body += f'<form method="post" action="/servers/{server_id}/onboard">'
        body += control(request)
        body += ('<label>Пароль пользователя SSH '
                 '<input type="password" name="ssh_password" required '
                 'autocomplete="off"></label>')
        body += ('<label><input type="checkbox" name="confirm_key_install" '
                 'value="yes" required>Разрешаю установить публичный ключ '
                 'для этого SSH-пользователя</label>')
        body += '<button>Установить ключ и проверить SSH</button></form></section>'
        return page(request, 'Первоначальная настройка SSH', body)

    @app.post('/servers/{server_id}/onboard')
    async def server_onboarding(request: Request, server_id: int):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        if data.get('confirm_key_install') != 'yes':
            raise HTTPException(400, 'Подтвердите установку публичного ключа.')
        # Dedicated in-memory throttle for the high-risk SSH password operation.
        attempts = app.state.ssh_enrollment_attempts
        actor = request.session['admin']
        key = (actor, server_id)
        now = asyncio.get_running_loop().time()
        recent = attempts.setdefault(key, [])
        recent[:] = [t for t in recent if now - t < 900]
        if len(recent) >= 5:
            raise HTTPException(429, 'Слишком много попыток SSH. Повторите позже.')
        with db.session() as session:
            item = session.get(SSHServer, server_id)
            if item is None:
                raise HTTPException(404)
            record = {name: getattr(item, name) for name in (
                'name', 'host', 'port', 'username', 'key_file', 'known_hosts_file')}
        recent.append(now)
        try:
            await enroll_public_key(record, cfg, data.get('ssh_password', ''))
            await probe_ssh(record, cfg)
        except EnrollmentError as exc:
            # Only a controlled, generic message. Never echo password or SSH
            # exception details, which can contain sensitive connection metadata.
            return page(request, 'Не удалось настроить SSH',
                        f'<section><p>{safe(exc)}</p>'
                        f'<a href="/servers/{server_id}/onboard">Повторить</a></section>')
        except Exception:
            return page(request, 'Ключ установлен, проверка не прошла',
                        '<section><p>Публичный ключ добавлен, но проверка SSH/TCP '
                        'forwarding не пройдена. Проверьте AllowTcpForwarding '
                        'и доступность HEALTH_TEST_HOST:PORT.</p>'
                        f'<a href="/servers/{server_id}/edit">Настройки сервера</a></section>')
        recent.clear()
        await ssh.refresh()
        await asyncio.to_thread(db.audit, actor, 'server_ssh_key_enrolled', str(server_id))
        return page(request, 'SSH успешно настроен',
                    '<section><p>Публичный ключ установлен. SSH и TCP forwarding '
                    'успешно проверены.</p><a href="/servers">К серверам</a></section>')

    @app.post('/servers/{server_id}/edit')
    async def server_edit(request: Request, server_id: int):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        fields = parse_server_form(data)
        with db.session() as session:
            if not session.get(SSHServer, server_id):
                raise HTTPException(404)
        try:
            await probe_ssh(fields, cfg)
        except Exception as exc:
            return page(request, 'Проверка не пройдена',
                        '<section>Изменения не сохранены. '
                        f'<a href="/servers/{server_id}/onboard">'
                        'Настроить SSH-доступ (установить ключ)</a> · '
                        '<a href="/servers">Назад</a></section>',
                        type(exc).__name__)
        with db.session() as session:
            item = session.get(SSHServer, server_id)
            if not item:
                raise HTTPException(404)
            for key, value in fields.items():
                setattr(item, key, value)
        await ssh.refresh()
        await asyncio.to_thread(db.audit, request.session['admin'], 'server_edit', str(server_id))
        return return_to('/servers')

    @app.post('/servers/{server_id}/check')
    async def server_check(request: Request, server_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        matches = [x for x in db.servers() if x['id'] == server_id]
        if not matches:
            raise HTTPException(404)
        try:
            await probe_ssh(matches[0], cfg)
        except Exception as exc:
            return page(request, 'SSH-диагностика',
                        '<p>Проверка SSH/TCP forwarding не пройдена.</p>'
                        f'<a href="/servers/{server_id}/onboard">'
                        'Настроить SSH-доступ (установить ключ)</a>',
                        type(exc).__name__)
        return page(request, 'SSH-диагностика', '<p>SSH и TCP forwarding: OK</p>')

    @app.post('/servers/{server_id}/reconnect')
    async def reconnect_server(request: Request, server_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as session:
            server = session.get(SSHServer, server_id)
            if not server:
                raise HTTPException(404)
            if not server.enabled:
                raise HTTPException(400, 'Server disabled')
        await ssh.reconnect(server_id)
        await asyncio.to_thread(db.audit, request.session['admin'], 'server_reconnect', str(server_id))
        return return_to('/servers')

    @app.post('/servers/{server_id}/primary')
    async def make_primary(request: Request, server_id: int):
        require_admin(request)
        check_csrf(request, await form_data(request))
        with db.session() as session:
            item = session.get(SSHServer, server_id)
            if not item:
                raise HTTPException(404)
            for i, other in enumerate(session.scalars(select(SSHServer).order_by(SSHServer.priority, SSHServer.id))):
                other.priority = i + 2
            item.priority = 1
        await ssh.refresh()
        await asyncio.to_thread(db.audit, request.session['admin'], 'server_primary', str(server_id))
        return return_to('/servers')

    @app.get('/clients/{client_id}/edit')
    async def client_edit_form(request: Request, client_id: int):
        require_admin(request)
        with db.session() as session:
            item = session.get(Client, client_id)
            if not item:
                raise HTTPException(404)
            fields = (item.name, item.max_connections, item.pinned_server_id or '', item.allow_fallback)
        body = '<section><form method="post" action="/clients/%d/edit">' % client_id + control(request)
        body += esc_input('name', fields[0], required=True)
        body += esc_input('max_connections', fields[1], 'number', True)
        body += esc_input('pinned_server_id', fields[2], 'number')
        body += '<label><input type="checkbox" name="allow_fallback" value="yes" %s>Разрешить резервный SSH</label>' % ('checked' if fields[3] else '')
        body += '<button>Сохранить</button></form></section>'
        body += '<section><h2>Сменить пароль</h2><form method="post" action="/clients/%d/password">' % client_id
        body += control(request) + esc_input('password', '', 'password')
        body += '<label><input type="checkbox" name="generate_password" value="yes">Создать безопасный пароль</label>'
        body += '<button>Сменить пароль</button></form></section>'
        return page(request, 'Настройки клиента', body)

    @app.post('/clients/{client_id}/edit')
    async def client_edit(request: Request, client_id: int):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        try:
            name = data['name'].strip()[:120]
            limit = int(data['max_connections'])
            pinned = int(data['pinned_server_id']) if data.get('pinned_server_id') else None
            if not name or not 1 <= limit <= 10000:
                raise ValueError
        except (ValueError, KeyError) as exc:
            raise HTTPException(400, 'Invalid client settings') from exc
        with db.session() as session:
            item = session.get(Client, client_id)
            if not item:
                raise HTTPException(404)
            if pinned and not session.get(SSHServer, pinned):
                raise HTTPException(400, 'Unknown SSH server')
            item.name, item.max_connections = name, limit
            item.pinned_server_id = pinned
            item.allow_fallback = data.get('allow_fallback') == 'yes'
        await asyncio.to_thread(db.audit, request.session['admin'], 'client_edit', str(client_id))
        return return_to('/clients')

    @app.post('/clients/{client_id}/password')
    async def client_password(request: Request, client_id: int):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        generated = data.get('generate_password') == 'yes'
        password = secrets.token_urlsafe(24) if generated else data.get('password', '')
        if len(password) < 12:
            raise HTTPException(400, 'Password min 12 characters')
        with db.session() as session:
            item = session.get(Client, client_id)
            if not item:
                raise HTTPException(404)
            item.password_hash = hasher.hash(password)
        for tunnel in list(socks.active.values()):
            if tunnel.client_id == client_id:
                await socks.disconnect(tunnel.id)
        await asyncio.to_thread(db.audit, request.session['admin'], 'client_password_reset', str(client_id))
        text = ('Пароль (показывается один раз): <code>%s</code>' % safe(password)
                if generated else 'Пароль изменён.')
        return page(request, 'Пароль клиента изменён', '<section>%s</section>' % text)

    @app.get('/admin/password')
    async def admin_password_form(request: Request):
        require_admin(request)
        body = '<section><form method="post" action="/admin/password">' + control(request)
        body += esc_input('current_password', '', 'password', True)
        body += esc_input('new_password', '', 'password', True)
        return page(request, 'Пароль администратора', body + '<button>Сменить</button></form></section>')

    @app.post('/admin/password')
    async def admin_password_change(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        actor = request.session['admin']
        if not await asyncio.to_thread(db.verify_admin, actor, data.get('current_password', '')):
            raise HTTPException(403, 'Wrong current password')
        if len(data.get('new_password', '')) < 12:
            raise HTTPException(400, 'New password min 12 characters')
        with db.session() as session:
            obj = session.scalar(select(Admin).where(Admin.username == actor))
            if not obj:
                raise HTTPException(404)
            obj.password_hash = hasher.hash(data['new_password'])
        await asyncio.to_thread(db.revoke_admin_sessions)
        await asyncio.to_thread(db.audit, actor, 'admin_password_change', 'own_password')
        request.session.clear()
        return return_to('/login')

    @app.get('/api/diagnostics')
    async def diagnostics(request: Request):
        require_admin(request)
        allowed = ('id', 'name', 'status', 'ready', 'active_channels', 'latency_ms',
                   'reconnect_count', 'last_error')
        return JSONResponse({
            'timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'version': __import__('osgate').__version__,
            'ssh_servers': [{key: record[key] for key in allowed} for record in ssh.candidates()],
            'active_connections': len(socks.active), 'completed_connections': socks.completed,
            'rejected_connections': socks.rejected,
        }, headers={'Cache-Control': 'no-store',
                    'Content-Disposition': 'attachment; filename="osgate-diagnostics.json"'})

    @app.get('/api/events.csv')
    async def export_events(request: Request):
        require_admin(request)
        with db.session() as session:
            events = list(session.scalars(select(Event).order_by(Event.id.desc()).limit(500)))
        stream = io.StringIO()
        writer = csv.writer(stream)
        writer.writerow(['UTC', 'Category', 'Event'])
        for record in events:
            writer.writerow([record.when, record.category, record.message])
        return Response(stream.getvalue(), media_type='text/csv; charset=utf-8',
                        headers={'Cache-Control': 'no-store',
                                 'Content-Disposition': 'attachment; filename="osgate-events.csv"'})

    @app.get('/settings/runtime')
    async def runtime_settings_form(request: Request):
        require_admin(request)
        from .settings_store import EDITABLE
        body = '<section><form method="post" action="/settings/runtime">' + control(request)
        for field in EDITABLE:
            body += esc_input(field, getattr(cfg, field), 'number', True, step='any')
        return page(request, 'Настройки работы', body + '<button>Сохранить</button></form></section>')

    @app.post('/settings/runtime')
    async def runtime_settings_save(request: Request):
        require_admin(request)
        data = await form_data(request)
        check_csrf(request, data)
        from .settings_store import persist_runtime_settings
        try:
            await asyncio.to_thread(persist_runtime_settings, db, cfg, data)
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(400, 'Invalid settings') from exc
        await asyncio.to_thread(db.audit, request.session['admin'], 'settings_change', 'operational')
        return return_to('/settings/runtime')

    @app.get('/api/metrics')
    async def metrics(request: Request):
        require_admin(request)
        up, down = await asyncio.to_thread(db.traffic_totals)
        samples = await asyncio.to_thread(db.recent_samples, 120)
        return JSONResponse({'uploaded': up + sum(t.uploaded for t in socks.active.values()),
                             'downloaded': down + sum(t.downloaded for t in socks.active.values()),
                             'active_connections': len(socks.active), 'samples': samples},
                            headers={'Cache-Control': 'no-store'})

    @app.get('/metrics')
    async def metrics_page(request: Request):
        require_admin(request)
        body = '''<section><h2>Передача данных</h2>
        <p>Отправлено: <strong id="up">—</strong> байт;
        Получено: <strong id="down">—</strong> байт;
        Соединений: <strong id="active">—</strong></p>
        <canvas id="chart" width="750" height="230" style="width:100%;max-width:750px"></canvas>
        <p class="muted">До 120 снимков с интервалом 60 секунд.</p></section>
        <script>
        async function refresh() {
          try {
            const r=await fetch('/api/metrics',{cache:'no-store'});
            if(!r.ok)return;
            const x=await r.json();
            for(const [id,v] of [['up',x.uploaded],['down',x.downloaded],['active',x.active_connections]])
              document.getElementById(id).textContent=v.toLocaleString('ru-RU');
            const can=document.getElementById('chart'),c=can.getContext('2d');
            c.clearRect(0,0,can.width,can.height);
            const v=x.samples.map(y=>y.active),n=v.length;
            if(!n)return;
            const peak=Math.max(1,...v);
            c.beginPath();c.strokeStyle='#59d394';c.lineWidth=2;
            v.forEach((y,i)=>{const a=20+(can.width-40)*(n===1?0.5:i/(n-1));
              const b=can.height-20-y/peak*(can.height-40);
              if(i===0)c.moveTo(a,b);else c.lineTo(a,b);});c.stroke();
          }catch(_){}
        }
        refresh();setInterval(refresh,10000);
        </script>'''
        return page(request, 'Графики трафика', body)
