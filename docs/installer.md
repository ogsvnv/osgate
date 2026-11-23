# Установка OSGate (мастер)

На новой машине можно начать одной командой:

```bash
curl -fsSL https://raw.githubusercontent.com/ogsvnv/osgate/main/bootstrap.sh | bash
```

Скрипт скачивает репозиторий в `~/osgate`, затем запускает интерактивный мастер
с правами администратора через `sudo`. Ввод паролей идёт напрямую через терминал.
Чтобы сразу выбрать Docker: `curl -fsSL https://raw.githubusercontent.com/ogsvnv/osgate/main/bootstrap.sh | bash -s -- --mode docker`.

**Без выполнения скрипта напрямую из сети:** `curl -fsSLo bootstrap.sh https://raw.githubusercontent.com/ogsvnv/osgate/main/bootstrap.sh`,
изучите его, затем выполните `bash bootstrap.sh`.

В репозитории предусмотрен интерактивный мастер **`install.sh`**. Он запускается локально из
проверенного клона GitHub на Ubuntu/Debian Linux и не требует curl|bash.

```bash
sudo apt-get update
sudo apt-get install -y git python3 openssl
git clone https://github.com/ogsvnv/osgate.git
cd osgate
sudo ./install.sh
```

Далее выберите **Docker Compose** (рекомендуется) либо **systemd**.
Для Docker необходимо заранее установить и запустить Docker Engine и Docker Compose plugin.
Для systemd необходимы Python 3.12+, venv/ensurepip, pip и права root.
Программа проверяет необходимые зависимости и объясняет ошибки. При отсутствии `python3.12-venv` в режиме systemd мастер может предложить установить пакет через apt после вашего явного согласия. Docker автоматически не устанавливается.

### Что спрашивает установщик

- Способ запуска: Docker Compose или systemd.
- Имя администратора OSGate (пароль вводится через скрытый интерактивный prompt CLI).
- Локальные порты веб-панели (по умолчанию **5812**) и SOCKS5 (**1080**).
- Добавлять ли SSH-сервер сейчас. Если да — его имя, IP/hostname, порт, имя SSH-пользователя,
  путь к **существующему** приватному ключу.
- Если нужного host key нет в известном и уже доверенном `known_hosts`,
  установщик покажет fingerprint. **Сверьте его с сервером через независимый канал**.
  Только после ручного подтверждения ключ будет принят.

Для SSH-клиента рекомендуется отдельный ключ без passphrase, предназначенный для OSGate.
SSH-сервер должен разрешать TCP forwarding. Веб-панель при необходимости позволяет
добавить/изменить сервер уже после установки.

**Важно:** система не создаёт ключи, не меняет удалённый `sshd_config`,
не загружает публичные SSH-ключи на удалённый сервер и не открывает firewall.
На серверах без проверенного SSH host key автоматическое подключение не включается.

### Доступ к панели

При настройках по умолчанию панель доступна на **http://127.0.0.1:5812**.
Порты публикуются только на loopback интерфейсе. Для доступа с другого устройства
настройте SSH-перенаправление:

```bash
ssh -L 5812:127.0.0.1:5812 username@OSGATE_SERVER
```

Затем откройте на своём компьютере http://127.0.0.1:5812.
Открывать административную панель напрямую в интернет не рекомендуется.

### Работа с установленным OSGate

Проверить работу Docker:

```bash
sudo ./install.sh --check --mode docker
docker compose logs --tail=100
```

Проверить службу systemd:

```bash
sudo ./install.sh --check --mode systemd
sudo systemctl status osgate
```

Обновить приложение, сохраняя `.env`, базу SQLite и SSH-ключи:

```bash
sudo ./install.sh --update --mode docker
# или
sudo ./install.sh --update --mode systemd
```

При обновлении мастер запросит подтверждение, сделает SQLite online backup, обновит
локальный код из текущего Git checkout (`git pull --ff-only`) и перезапустит службу/контейнер.
Резервные копии SQLite сохраняются в `backups/`.
Если используете отдельную production-ветку или зафиксированный релиз, сначала выберите
правильный Git ref, а уже затем запускайте обновление.

Установщик **отказывается перезаписать существующую конфигурацию при повторной установке**.
Для уже работающего приложения используйте `--update`. Не выполняйте вручную
`docker compose down -v`, если хотите сохранить данные.

### Дополнительные команды

```bash
./install.sh --help
./install.sh --check --mode docker
sudo ./install.sh --mode docker
sudo ./install.sh --mode systemd
```

Проверка системного healthcheck подтверждает работоспособность процесса и HTTP-панели,
**но не заменяет проверку SSH-транспорта и выхода в интернет**. После установки добавьте
SOCKS5-клиента и проверьте запрос через `curl --proxy socks5h://...` согласно README.
