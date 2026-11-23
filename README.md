# OSGate (alpha 0.1.0)

OSGate — SOCKS5-шлюз, который открывает целевые TCP-соединения **исключительно через SSH `direct-tcpip`**. Требуется Python 3.12+, стандартный OpenSSH Server на удалённом узле (`AllowTcpForwarding yes`). Не требуется `ssh -D` и не используется локальный интернет вместо SSH. Поддерживаются IPv4, IPv6, домены с удалённым DNS, клиентская авторизация RFC1929, постоянные SSH-транспорты, несколько серверов, переключение **новых** TCP-соединений, SQLite, русскоязычная веб-панель и Telegram-оповещения. Текущая версия — **alpha**, не прошла боевое тестирование.

## Как работает

`Приложение → SOCKS5:1080 (авторизация) → OSGate → AsyncSSH transport → SSH direct-tcpip → нужный хост:порт`.

При потере соединения действующие TCP-сеансы завершаются. Новые используют резервный маршрут. При отсутствии исправного SSH возвращается ошибка SOCKS5, **никакого прямого подключения**. `socks5h://` передаёт домен на прокси, тогда как `socks5://` в curl может разрешить домен локально.

## Docker Compose

1. `git clone https://github.com/ogsvnv/osgate.git && cd osgate`
2. `cp .env.example .env && sed -i "s|SESSION_SECRET=.*|SESSION_SECRET=$(openssl rand -hex 32)|" .env`
3. `mkdir -p data ssh && sudo chown 10001:10001 data` (если хостовые файловые права требуют).
4. Разместить отдельный SSH-ключ в `ssh/id_ed25519` и проверить его права; файл `ssh/known_hosts` должен содержать **проверенный вручную** fingerprint удалённого сервера. Не допускается `known_hosts=None`. Для добавления hosts можно собрать ключ `ssh-keyscan -H server.example >> ssh/known_hosts`, **сверив fingerprint через доверенный канал** перед доверием ключу. Каталог `ssh/` не публиковать в Git.
5. `docker compose build`.
6. `docker compose run --rm --entrypoint osgate osgate admin create admin` — интерактивно введите пароль ≥12 символов.
7. `docker compose up -d`.
8. `http://127.0.0.1:5812` — панель администратора. Внесите SSH-сервер с ключом `/ssh/id_ed25519` и `/ssh/known_hosts`. Сервер сохраняется только при успешном SSH и TCP forwarding probe (настраивается HEALTH_TEST_HOST:PORT).
9. Добавьте клиента SOCKS5 на странице «Клиенты».
10. Проверьте:

```bash
curl --proxy socks5h://127.0.0.1:1080 --proxy-user 'user:password' https://api.ipify.org
```

Внешний IP должен совпадать с IP удалённого SSH-хоста. Для доступа к SOCKS5 с других компьютеров настройте привязку портов в Compose и firewall **только для доверенных IP**. По умолчанию оба порта опубликованы на localhost.

В контейнере веб-слушатель работает на `0.0.0.0:5812`, но проброс на хост ограничен `127.0.0.1`. Docker bridge передаёт запросы с IP шлюза (обычно `172.16.0.0/12`), поэтому Compose явно задаёт `WEB_ALLOWED_CIDRS` для loopback и стандартного диапазона Docker bridge. Для более строгой конфигурации задайте в `.env` `DOCKER_WEB_ALLOWED_CIDRS=127.0.0.1/32,::1/128,<адрес_Docker_gateway>/32`, проверив IP gateway своей Docker-сети. Доступ из других контейнеров той же сети контролируйте отдельно. Не открывайте административный порт наружу без HTTPS, авторизации и точных сетевых ограничений. При настройке HTTPS reverse proxy установите `WEB_SECURE_COOKIES=true` и настройте доверенные IP/CIDR, учитывая IP reverse proxy.

## systemd (без Docker)

Перед установкой убедитесь, что есть Python 3.12+ и поддержка `venv`: `python3 -m venv /tmp/osgate-venv-check && rm -rf /tmp/osgate-venv-check`. На Debian/Ubuntu при сообщении об отсутствующем `ensurepip` установите через администратора `python3-venv` (или `python3.12-venv`). Установщик проверяет это заранее и ничего не изменяет при отсутствии пакета. Скопируйте проект в `/opt/osgate`, запустите `sudo bash deploy/install.sh`. Отредактируйте `/etc/osgate/osgate.env`, создайте SSH-ключи в `/etc/osgate/ssh`, создайте администратора с окружением из systemd (см. вывод установщика) и запустите `sudo systemctl enable --now osgate`. Для CLI при systemd используйте `EnvironmentFile`, не размещайте секреты в shell history. Установщик **не меняет firewall**. Для UFW разрешайте только нужные адреса: `sudo ufw allow from <CLIENT_IP> to any port 1080 proto tcp`; админ-порт 5812 оставляйте на loopback. Проверяйте сохранение доступа к SSH до правок firewall.

### CLI

`osgate start`, `osgate version`, `osgate check`, `osgate status`, `osgate config validate`, `osgate admin create admin`, `osgate admin reset-password admin`, `osgate server list`, `osgate server add --name ... --host ... --username ... --key-file /ssh/id_ed25519 --known-hosts-file /ssh/known_hosts`, `osgate server check ID`, `osgate client list`, `osgate client add username`. Прямое изменение серверов через CLI требует перезапуска сервиса, web CRUD — нет.

### Переключение серверов

В панели выберите `failover`, `round_robin`, `weighted_round_robin`, `manual` или `sticky`. Заданные приоритеты используются в режиме failover. Для закреплённого клиента можно запретить переключение либо разрешить резерв. Состояния ONLINE/DEGRADED/OFFLINE отслеживаются независимыми асинхронными задачами. Если внешний адрес проверки из `HEALTH_TEST_HOST:PORT` блокируется на SSH-хосте, выберите доступный TCP endpoint через `.env`.

### Telegram

В `.env` задайте `TELEGRAM_ENABLED=true`, `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID`. Отправка не блокирует сетевую обработку; события подавляются при повторе в течение 60 секунд. Не размещайте токены в открытом репозитории.

### Диагностика

`docker compose ps`, `docker compose logs --tail=100`, `osgate check`, веб-панель «Журнал». Команда `curl` с `socks5h://` исключает локальный DNS. Убедитесь, что `AllowTcpForwarding yes` разрешён для нужного пользователя OpenSSH, а сервер видит интернет и известен `known_hosts`.

### Обновление / резервное копирование

Остановите контейнер, сделайте резервную копию `.env`, `data/osgate.db` (или SQLite online backup при работающем приложении) и приватных ключей, обновите исходники, пересоберите образ, выполните `docker compose up -d`. Миграции Alembic применяются на старте. Для восстановления верните persistent data, `.env` и SSH файлы, затем запустите контейнер. Для удаления: `docker compose down`, после безопасного бэкапа удалите каталог только вручную, чтобы не потерять данные.

### Известные ограничения alpha

- Реализован SOCKS5 CONNECT/TCP. SOCKS BIND, UDP ASSOCIATE не поддерживаются (возвращается `0x07`).
- Нет полноценного редактирования клиента и сервера, смены пароля клиента, live-edit сетевых настроек, полноценного DNS health, графиков и сохранения подробной истории соединений; не позиционируется как версия 1.0.
- Нет автоматического развертывания SSH-ключей или UI подтверждения fingerprint; доверие задаётся через отдельный защищённый файл known_hosts.
- Зашифрованные приватные SSH-ключи без агента не поддерживаются в текущей alpha (требуется отдельная схема защищённого passphrase secret).
- Нагрузочные испытания 100/500/1000 соединений не пройдены; производительность не гарантируется.
- Базовый E2E с реальным OpenSSH на `park` выполнен (внешний IP и отсутствие прямого fallback), также выполнен тест client-side разрыва и reconnect. Тест двух реальных SSH-серверов и полный производственный аудит ещё не выполнены. Интеграционные тесты `tests/integration/` по умолчанию пропускаются без явных переменных `OSGATE_E2E_*`.

См. `tests/` и GitHub Actions. Не выставляйте пока публичный SOCKS5/админ-порт без дополнительных ограничений и аудита.
