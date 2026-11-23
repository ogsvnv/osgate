"""OSGate CLI. `start` owns the listening ports; other commands only open DB."""
import argparse
import getpass
import os
import secrets
import sys
import uvicorn
from sqlalchemy import select
from . import __version__
from .config import Settings
from .database import Database, Admin, Client, SSHServer, hasher


def main(argv=None):
    p = argparse.ArgumentParser(prog='osgate')
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('start', 'check', 'status', 'version'):
        sub.add_parser(name)
    admin = sub.add_parser('admin')
    admin_cmd = admin.add_subparsers(dest='action', required=True)
    for name in ('create', 'reset-password'):
        entry = admin_cmd.add_parser(name)
        entry.add_argument('username')
    server = sub.add_parser('server')
    server_cmd = server.add_subparsers(dest='action', required=True)
    server_cmd.add_parser('list')
    srv_add = server_cmd.add_parser('add')
    for key in ('name', 'host', 'username', 'key-file', 'known-hosts-file'):
        srv_add.add_argument('--' + key, required=True)
    srv_add.add_argument('--port', type=int, default=22)
    srv_add.add_argument('--priority', type=int, default=100)
    srv_add.add_argument('--weight', type=int, default=1)
    srv_chk = server_cmd.add_parser('check')
    srv_chk.add_argument('id', type=int)
    client = sub.add_parser('client')
    client_cmd = client.add_subparsers(dest='action', required=True)
    client_cmd.add_parser('list')
    add = client_cmd.add_parser('add')
    add.add_argument('username')
    add.add_argument('--name', default='')
    config_cmd = sub.add_parser('config')
    config_cmd.add_subparsers(dest='action', required=True).add_parser('validate')

    args = p.parse_args(argv)
    if args.command == 'version':
        print(__version__)
        return
    cfg = Settings()
    if args.command == 'config' and args.action == 'validate':
        cfg.validate_runtime()
        print('Configuration OK')
        return
    if args.command == 'start':
        cfg.validate_runtime()
        uvicorn.run('osgate.cli:app_factory', host=cfg.web_host, port=cfg.web_port,
                    factory=True, access_log=False)
        return
    db = Database(cfg.database_url)
    db.initialize()
    if args.command == 'check':
        print('SQLite OK; configured SSH servers:', len(db.servers()))
    elif args.command == 'status':
        print('Configured SSH servers:', len(db.servers()))
        print('Mode:', db.routing()['mode'])
        print('Live health available at web /api/status after login')
    elif args.command == 'admin':
        pwd = getpass.getpass('New administrator password (min 12 chars): ')
        if len(pwd) < 12:
            raise SystemExit('Password must be at least 12 characters')
        with db.session() as s:
            record = s.scalar(select(Admin).where(Admin.username == args.username))
            if args.action == 'create' and record:
                raise SystemExit('Administrator already exists')
            if args.action == 'reset-password' and not record:
                raise SystemExit('Administrator not found')
            if record:
                record.password_hash = hasher.hash(pwd)
            else:
                s.add(Admin(username=args.username, password_hash=hasher.hash(pwd)))
        db.revoke_admin_sessions()
        print('Administrator credentials saved')
    elif args.command == 'server' and args.action == 'list':
        for rec in db.servers():
            print(f"{rec['id']:4} {rec['name']:24} {rec['host']}:{rec['port']}  enabled={rec['enabled']}")
    elif args.command == 'server' and args.action == 'add':
        from pathlib import Path
        root = cfg.ssh_directory.resolve()
        for path in (args.key_file, args.known_hosts_file):
            if not Path(path).resolve(strict=True).is_relative_to(root):
                raise SystemExit('Credential path must be within SSH_DIRECTORY')
        with db.session() as s:
            s.add(SSHServer(name=args.name, host=args.host, port=args.port,
                            username=args.username, key_file=args.key_file,
                            known_hosts_file=args.known_hosts_file,
                            priority=args.priority, weight=args.weight))
        print('Server added. Restart or reload the OSGate service to activate CLI changes.')
    elif args.command == 'server' and args.action == 'check':
        import asyncio
        from .ssh import connect_ssh
        records = [x for x in db.servers() if x['id'] == args.id]
        if not records:
            raise SystemExit('Unknown server')
        async def test():
            conn = await connect_ssh(records[0], cfg)
            try:
                reader, writer = await conn.open_connection(cfg.health_test_host, cfg.health_test_port)
                writer.close()
                print('Verified SSH and remote TCP forwarding')
            finally:
                conn.close()
                await conn.wait_closed()
        asyncio.run(test())
    elif args.command == 'client' and args.action == 'list':
        with db.session() as s:
            for u in s.scalars(select(Client)):
                print(f'{u.id:4} {u.username:24} enabled={u.enabled}')
    elif args.command == 'client' and args.action == 'add':
        pwd = getpass.getpass('SOCKS5 password (min 12 chars): ')
        if len(pwd) < 12:
            raise SystemExit('Password must be at least 12 characters')
        with db.session() as s:
            s.add(Client(name=args.name or args.username, username=args.username,
                         password_hash=hasher.hash(pwd)))
        print('SOCKS5 client added')


def app_factory():
    from .app import create_app
    return create_app()


if __name__ == '__main__':
    main()
