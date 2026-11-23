# OSGate 0.1.0 alpha — проверка Docker и systemd (23.11.2026)

Это протокол испытаний alpha-сборки, **не** свидетельство production-ready версии 1.0.

## Условия
- Docker 29.10.0 на тестовом Linux-хосте `lenovo`. Контейнер и Docker volume имели отдельные тестовые имена, HTTP/SOCKS проброшены только на `127.0.0.1:15812/11080`.
- systemd 259 на `lenovo`. Запускался временный **systemd --user** service с ограничениями `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, отдельной БД и окружением. Это **не** установка root system unit по постоянным путям `/opt/osgate` и `/etc/osgate`.
- На `park`: Docker 29.10.0, systemd 255, Python 3.12.3. У пользователя нет passwordless sudo, а `python3 -m venv` завершается ошибкой отсутствия `ensurepip`/`python3.12-venv`. Существующие службы и firewall `park` не менялись.

## Результаты Docker
1. `docker build` из текущего кода: **OK**.
2. Запуск с непривилегированным UID, без дополнительных capabilities, с Docker healthcheck: **OK**.
3. Запуск без SSH-серверов не приводит к постоянным рестартам; встроенный healthcheck: **OK**.
4. Сначала запрос с хоста на опубликованный localhost-порт возвращал **403**, поскольку приложение видело IP Docker bridge gateway. Исправлено: Compose задаёт bridge-aware `WEB_ALLOWED_CIDRS` с возможностью переопределить через `DOCKER_WEB_ALLOWED_CIDRS`. После этого `/healthz` и `/login` вернули **HTTP 200**.
5. После остановки, удаления и пересоздания тестового контейнера с тем же persistent volume сохранилась ранее записанная тестовая строка SQLite; рестартов по ошибке: **0**.
6. `docker compose config --quiet`: **OK**.

Изменение CIDR в Docker Compose расширяет сетевые адреса, принимаемые приложением внутри контейнера; **хостовый порт по-прежнему опубликован только на loopback**. Для строгой изоляции укажите конкретный IP Docker gateway/32 в `DOCKER_WEB_ALLOWED_CIDRS` и контролируйте другие контейнеры в Docker-сети.

## Результаты systemd
1. Приложение запущено через `systemd-run --user` c ограничениями доступа и собственным `EnvironmentFile`: `active (running)`, `/healthz`: **HTTP 200**, `NRestarts=0`.
2. `systemctl --user restart`: новый PID, `/healthz`: **HTTP 200**.
3. Сохранность данных SQLite после рестарта: **OK**.
4. `systemctl --user stop`: `inactive`, `Result=success`, HTTP listener закрыт, штатные сообщения shutdown в journald: **OK**.
5. `deploy/install.sh`: `bash -n` — **OK**. Добавлен preflight `venv` до создания пользователей, каталогов и конфигураций и исправлена команда создания администратора.

## Автоматические тесты
`pytest -q`: **10 passed, 2 skipped** в локальном окружении. Два интеграционных теста с настоящим SSH по умолчанию пропускаются без `OSGATE_E2E_*`. До этой проверки на `park` успешно проходили отдельные E2E-тесты SOCKS5→SSH→Internet и reconnect.

## Что пока не подтверждено
- Запуск постоянного **системного** `osgate.service` на `park` (для установки Python venv и unit-файла нужны права администратора). Текущий тест systemd проверяет аналогичный пользовательский transient unit на `lenovo`.
- Работа Docker-образа на самом `park` (Docker-сценарий выполнялся на `lenovo`, чтобы не влиять на существующие контейнеры).
- Docker end-to-end через реальный `park`, работа с TLS reverse proxy, multi-server failover/failback и длительная нагрузка 100/500/1000 соединений.

Тестовые контейнеры, тома и временный пользовательский systemd-unit должны быть удалены по окончании испытаний. Нельзя трактовать этот протокол как одобрение установки alpha в production.
