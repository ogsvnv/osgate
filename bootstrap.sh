#!/usr/bin/env bash
# Bootstrap OSGate from the official GitHub repository.
# Pipe-safe: sudo and the interactive wizard always read from /dev/tty.
set -Eeuo pipefail

REPO_URL='https://github.com/ogsvnv/osgate.git'
DEFAULT_REF='main'
INSTALL_MODE=''
ACTION='install'
TARGET_DIR="${OSGATE_INSTALL_DIR:-}"

usage() {
  cat <<'HELP'
OSGate — установка на новую машину
  curl -fsSL https://raw.githubusercontent.com/ogsvnv/osgate/main/bootstrap.sh | bash

Параметры:
  --mode docker|systemd   Выбрать способ установки (иначе интерактивный выбор)
  --dir PATH              Каталог для исходников (по умолчанию ~/osgate)
  --check                 Проверить ранее установленный OSGate
  --update                Обновить ранее установленный OSGate
  --access                Изменить доступ к SOCKS5 без переустановки
  -h, --help              Показать справку

Для установки необходимы: Linux, bash, git, python3, curl или wget
(скачивание самого bootstrap уже выполняется через curl).
Bootstrap не устанавливает Docker автоматически и не изменяет firewall.
HELP
}

fail() { printf '\nОшибка: %s\n' "$*" >&2; exit 1; }
say() { printf '\n%s\n' "$*"; }

while (($#)); do
  case "$1" in
    --mode)
      (($# >= 2)) || fail "Укажите docker или systemd после --mode"
      case "$2" in docker|systemd) INSTALL_MODE="$2";; *) fail "Неизвестный режим: $2";; esac
      shift 2;;
    --dir)
      (($# >= 2)) || fail "Укажите путь после --dir"
      TARGET_DIR="$2"
      shift 2;;
    --check)
      [[ "$ACTION" == install ]] || fail "Выберите только одно действие"
      ACTION='check'; shift;;
    --update)
      [[ "$ACTION" == install ]] || fail "Выберите только одно действие"
      ACTION='update'; shift;;
    --access)
      [[ "$ACTION" == install ]] || fail "Выберите только одно действие"
      ACTION='access'; shift;;
    --help|-h)
      usage; exit 0;;
    *) fail "Неизвестный параметр: $1";;
  esac
done

[[ "$(uname -s)" == Linux ]] || fail "Поддерживается только Linux."
command -v git >/dev/null || fail "Git не найден. На Ubuntu/Debian установите: sudo apt install git"
command -v python3 >/dev/null || fail "Python3 не найден. На Ubuntu/Debian установите: sudo apt install python3"
command -v sudo >/dev/null || [[ "${EUID}" -eq 0 ]] || fail "Не найден sudo. Выполните установку от root или установите sudo."
[[ -e /dev/tty && -r /dev/tty && -w /dev/tty ]] || fail "Нужен интерактивный терминал для безопасного ввода паролей."
# An unprivileged shell is preferred: clone into the invoking user's home.
if [[ -z "$TARGET_DIR" ]]; then
  if [[ "${EUID}" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
    command -v getent >/dev/null || fail "Не найдена getent"
    user_home="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
    [[ -n "$user_home" ]] || fail "Не удалось определить домашний каталог пользователя"
    TARGET_DIR="$user_home/osgate"
  else
    TARGET_DIR="$HOME/osgate"
  fi
fi
[[ "$TARGET_DIR" = /* ]] || fail "Каталог установки должен быть абсолютным."
[[ "$TARGET_DIR" != "/" ]] || fail "Недопустимый каталог установки."
case "$TARGET_DIR" in *$'\n'*|*$'\r'*) fail "Недопустимый путь к каталогу";; esac

say "OSGate · установка из официального репозитория"
printf 'Репозиторий: %s\nКаталог: %s\n' "$REPO_URL" "$TARGET_DIR"

if [[ -e "$TARGET_DIR" || -L "$TARGET_DIR" ]]; then
  [[ -d "$TARGET_DIR" && ! -L "$TARGET_DIR" ]] || fail "Путь уже занят файлом/символической ссылкой."
  [[ -d "$TARGET_DIR/.git" ]] || fail "Каталог занят другой установкой: $TARGET_DIR"
  origin="$(git -C "$TARGET_DIR" remote get-url origin 2>/dev/null)" || fail "Не удалось проверить удалённый репозиторий."
  case "$origin" in
    'https://github.com/ogsvnv/osgate.git'|'https://github.com/ogsvnv/osgate'|'git@github.com:ogsvnv/osgate.git'|'ssh://git@github.com/ogsvnv/osgate.git')
      ;;
    *) fail "Существующий каталог связан с другим Git-репозиторием. Не изменяю его.";;
  esac
  if [[ "$ACTION" == install ]]; then
    fail "OSGate уже скачан в $TARGET_DIR. Для обновления используйте --update."
  fi
  # Updating is handled by deploy/wizard.py and includes an explicit backup step.
else
  [[ "$ACTION" == install ]] || fail "Не найден OSGate в $TARGET_DIR. Сначала выполните установку."
  mkdir -p "$(dirname "$TARGET_DIR")"
  say "Скачивание OSGate..."
  git clone --depth 1 --branch "$DEFAULT_REF" -- "$REPO_URL" "$TARGET_DIR" </dev/tty
fi

[[ -f "$TARGET_DIR/install.sh" && -f "$TARGET_DIR/deploy/wizard.py" ]] || fail "Мастер установки отсутствует в репозитории."
args=()
[[ -n "$INSTALL_MODE" ]] && args+=(--mode "$INSTALL_MODE")
case "$ACTION" in
  check) args+=(--check);;
  update) args+=(--update);;
  access) args+=(--access);;
esac

say "Запуск мастера OSGate. Пароли будут вводиться через терминал."
if [[ "${EUID}" -eq 0 ]]; then
  (cd "$TARGET_DIR" && bash ./install.sh "${args[@]}" </dev/tty)
else
  (cd "$TARGET_DIR" && sudo bash ./install.sh "${args[@]}" </dev/tty)
fi
