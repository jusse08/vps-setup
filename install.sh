#!/bin/bash
# =============================================================
# VPS Setup Tool — Первый запуск / Fail2ban / sysctl
# Использование: bash install.sh
# =============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIGS_DIR="$SCRIPT_DIR/configs"
SYSCTL_FILE="/etc/sysctl.d/99-custom.conf"
BACKUP_FILE="/etc/sysctl.d/99-custom.conf.bak"

ok()      { echo -e "  ${GREEN}✓${NC}  $1"; }
warn()    { echo -e "  ${YELLOW}⚠${NC}  $1"; }
fail()    { echo -e "  ${RED}✗${NC}  $1"; }
info()    { echo -e "  ${CYAN}→${NC}  $1"; }
section() { echo -e "\n${BOLD}${BLUE}══ $1 ══${NC}\n"; }

# --- Root проверка ---
if [ "$EUID" -ne 0 ]; then
    echo -e "\n${RED}Запусти скрипт от root:${NC} sudo bash install.sh\n"
    exit 1
fi

# =============================================================
# Вспомогательные функции
# =============================================================

# Проверка папки configs/ — только для sysctl опций
check_configs_dir() {
    if [ ! -d "$CONFIGS_DIR" ]; then
        fail "Папка configs/ не найдена рядом со скриптом"
        info "Ожидаемая структура:"
        echo "      install.sh"
        echo "      configs/"
        echo "        ├── vpn-node.conf"
        echo "        ├── panel.conf"
        echo "        └── bot.conf"
        exit 1
    fi
}

# Определить текущий SSH порт из конфигов
get_ssh_port() {
    local port=""

    # Сначала проверяем наш drop-in
    if [ -f /etc/ssh/sshd_config.d/99-hardened.conf ]; then
        port=$(grep -i "^Port " /etc/ssh/sshd_config.d/99-hardened.conf 2>/dev/null | awk '{print $2}' | head -1)
    fi

    # Затем другие drop-in файлы
    if [ -z "$port" ] && [ -d /etc/ssh/sshd_config.d ]; then
        port=$(grep -rhi "^Port " /etc/ssh/sshd_config.d/ 2>/dev/null | awk '{print $2}' | head -1)
    fi

    # Затем основной конфиг
    if [ -z "$port" ]; then
        port=$(grep -i "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    fi

    echo "${port:-22}"
}

# =============================================================
# Функция 1: Базовая настройка VPS
# =============================================================
run_initial_setup() {
    clear
    echo -e "${BOLD}"
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │         Базовая настройка VPS           │"
    echo "  │  Пользователь · SSH · UFW               │"
    echo "  └─────────────────────────────────────────┘"
    echo -e "${NC}"

    # ── Создание пользователя ────────────────────────────────
    section "Создание пользователя"

    while true; do
        read -rp "  Имя нового пользователя: " NEW_USER
        if [[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            break
        else
            fail "Недопустимое имя. Используй строчные буквы, цифры, _ и -"
        fi
    done

    if id "$NEW_USER" &>/dev/null; then
        warn "Пользователь $NEW_USER уже существует — пропускаю создание"
    else
        adduser --gecos "" "$NEW_USER"
        if [ $? -eq 0 ]; then
            ok "Пользователь ${BOLD}$NEW_USER${NC} создан"
        else
            fail "Не удалось создать пользователя"
            exit 1
        fi
    fi

    # ── Добавление в sudo ────────────────────────────────────
    section "Права sudo"
    usermod -aG sudo "$NEW_USER"
    ok "Пользователь $NEW_USER добавлен в группу sudo"

    # ── SSH ключ ─────────────────────────────────────────────
    section "SSH-ключ"

    SSH_DIR="/home/$NEW_USER/.ssh"
    AUTH_FILE="$SSH_DIR/authorized_keys"

    mkdir -p "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    ok "Каталог $SSH_DIR создан (права 700)"

    echo ""
    echo -e "  ${CYAN}Вставь публичный SSH-ключ (начинается с ssh-rsa / ssh-ed25519 / ecdsa-sha2-...):${NC}"
    read -rp "  > " PUB_KEY

    if [[ ! "$PUB_KEY" =~ ^(ssh-rsa|ssh-ed25519|ssh-ecdsa|ecdsa-sha2-nistp|sk-ssh-) ]]; then
        warn "Ключ не похож на стандартный публичный SSH-ключ — добавляю как есть"
    fi

    echo "$PUB_KEY" >> "$AUTH_FILE"
    chmod 600 "$AUTH_FILE"
    chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"
    ok "Ключ добавлен в $AUTH_FILE (права 600)"

    # ── SSH конфиг ───────────────────────────────────────────
    section "Настройка SSH"

    while true; do
        read -rp "  Порт SSH (рекомендуется 1024–65535, не 22): " SSH_PORT
        if [[ "$SSH_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ]; then
            break
        else
            fail "Некорректный порт. Введи число от 1 до 65535"
        fi
    done

    SSHD_DROP_IN="/etc/ssh/sshd_config.d/99-hardened.conf"
    mkdir -p /etc/ssh/sshd_config.d

    cat > "$SSHD_DROP_IN" << EOF
# Hardened SSH config — создан VPS Setup Tool
# Чтобы откатить: rm $SSHD_DROP_IN && systemctl restart ssh

Port $SSH_PORT
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PubkeyAuthentication yes
PermitRootLogin no
AllowUsers $NEW_USER
EOF

    ok "Конфиг SSH записан: $SSHD_DROP_IN"

    # ── Проверка синтаксиса sshd ─────────────────────────────
    section "Проверка конфига SSH"
    if sshd -t 2>&1; then
        ok "sshd -t прошёл без ошибок"
    else
        fail "sshd -t обнаружил ошибки — проверь $SSHD_DROP_IN"
        info "SSH НЕ перезапущен во избежание блокировки"
        exit 1
    fi

    # ── UFW ──────────────────────────────────────────────────
    section "Настройка UFW"

    if ! command -v ufw &>/dev/null; then
        info "UFW не найден — устанавливаю..."
        apt install -y ufw
        ok "UFW установлен"
    else
        ok "UFW уже установлен"
    fi

    ufw default deny incoming  > /dev/null
    ufw default allow outgoing > /dev/null
    ok "Политики: deny incoming / allow outgoing"

    ufw allow 80/tcp  > /dev/null
    ufw allow 443/tcp > /dev/null
    ok "Открыты порты 80/tcp и 443/tcp"

    ufw allow "$SSH_PORT"/tcp > /dev/null
    ok "Открыт SSH порт $SSH_PORT/tcp"

    echo ""
    read -rp "  Это VPN нода? Нужно открыть порт от панели? [y/N]: " IS_NODE
    if [[ "$IS_NODE" =~ ^[Yy]$ ]]; then
        while true; do
            read -rp "  IP панели: " PANEL_IP
            if [[ "$PANEL_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                break
            else
                fail "Некорректный IP. Пример: 1.2.3.4"
            fi
        done

        while true; do
            read -rp "  Порт панели: " PANEL_PORT
            if [[ "$PANEL_PORT" =~ ^[0-9]+$ ]] && [ "$PANEL_PORT" -ge 1 ] && [ "$PANEL_PORT" -le 65535 ]; then
                break
            else
                fail "Некорректный порт"
            fi
        done

        ufw allow from "$PANEL_IP" to any port "$PANEL_PORT" > /dev/null
        ok "Разрешён входящий трафик с $PANEL_IP на порт $PANEL_PORT"
    fi

    ufw reload > /dev/null
    echo "y" | ufw enable > /dev/null
    ok "UFW включён и перезагружен"

    echo ""
    ufw status numbered

    # ── Перезапуск SSH ───────────────────────────────────────
    section "Перезапуск SSH"
    if systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null; then
        ok "SSH успешно перезапущен"
    else
        fail "Не удалось перезапустить SSH — сделай вручную: systemctl restart ssh"
    fi

    # ── Итог ─────────────────────────────────────────────────
    section "Готово"
    ok "Базовая настройка VPS завершена"
    echo ""
    echo -e "  ${BOLD}⚠  До выхода из текущей сессии — проверь вход:${NC}"
    echo ""
    echo -e "    ${CYAN}ssh -p $SSH_PORT $NEW_USER@<IP сервера>${NC}"
    echo ""
    warn "Не закрывай root-сессию, пока не убедишься что новый вход работает!"
    echo ""
    info "Откат SSH:"
    echo "    rm $SSHD_DROP_IN && systemctl restart ssh"
    echo ""
}

# =============================================================
# Функция 2: Установка и настройка Fail2ban
# =============================================================
run_fail2ban_setup() {
    clear
    echo -e "${BOLD}"
    echo "  ┌─────────────────────────────────────────┐"
    echo "  │         Установка Fail2ban              │"
    echo "  │  Защита SSH от брутфорса                │"
    echo "  └─────────────────────────────────────────┘"
    echo -e "${NC}"

    # ── Установка ────────────────────────────────────────────
    section "Установка пакета"

    if command -v fail2ban-client &>/dev/null; then
        ok "Fail2ban уже установлен: $(fail2ban-client --version 2>&1 | head -1)"
    else
        info "Устанавливаю fail2ban..."
        apt update -qq
        apt install -y fail2ban
        if command -v fail2ban-client &>/dev/null; then
            ok "Fail2ban установлен успешно"
        else
            fail "Ошибка установки fail2ban"
            exit 1
        fi
    fi

    # ── Определяем SSH порт ──────────────────────────────────
    section "Определение SSH порта"

    DETECTED_PORT=$(get_ssh_port)
    info "Обнаруженный SSH порт: ${BOLD}$DETECTED_PORT${NC}"

    echo ""
    read -rp "  Использовать этот порт? [Y/n]: " USE_DETECTED
    if [[ "$USE_DETECTED" =~ ^[Nn]$ ]]; then
        while true; do
            read -rp "  Введи SSH порт вручную: " DETECTED_PORT
            if [[ "$DETECTED_PORT" =~ ^[0-9]+$ ]] && [ "$DETECTED_PORT" -ge 1 ] && [ "$DETECTED_PORT" -le 65535 ]; then
                break
            else
                fail "Некорректный порт. Введи число от 1 до 65535"
            fi
        done
    fi

    ok "Будет использован порт: ${BOLD}$DETECTED_PORT${NC}"

    # ── Подготовка jail.local ────────────────────────────────
    section "Подготовка конфига"

    JAIL_CONF="/etc/fail2ban/jail.conf"
    JAIL_LOCAL="/etc/fail2ban/jail.local"

    if [ ! -f "$JAIL_CONF" ]; then
        fail "Файл $JAIL_CONF не найден — установка повреждена?"
        exit 1
    fi

    if [ -f "$JAIL_LOCAL" ]; then
        JAIL_BAK="${JAIL_LOCAL}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$JAIL_LOCAL" "$JAIL_BAK"
        ok "Существующий jail.local сохранён: $JAIL_BAK"
    else
        cp "$JAIL_CONF" "$JAIL_LOCAL"
        ok "Создан jail.local из jail.conf"
    fi

    # ── Патчим секцию [sshd] ─────────────────────────────────
    section "Настройка jail [sshd]"

    python3 - "$JAIL_LOCAL" "$DETECTED_PORT" << 'PYEOF'
import sys, re

jail_file = sys.argv[1]
ssh_port  = sys.argv[2]

with open(jail_file, 'r') as f:
    content = f.read()

new_sshd = (
    "[sshd]\n"
    "enabled  = true\n"
    f"port     = {ssh_port}\n"
    "filter   = sshd\n"
    "logpath  = /var/log/auth.log\n"
    "maxretry = 3\n"
    "bantime  = 3600\n"
    "findtime = 600\n"
    "backend  = %(sshd_backend)s\n"
)

# Заменяем существующую секцию [sshd] или добавляем в конец
pattern = r'\[sshd\].*?(?=\n\[|\Z)'
if re.search(pattern, content, re.DOTALL):
    content = re.sub(pattern, new_sshd.rstrip(), content, flags=re.DOTALL)
else:
    content += "\n" + new_sshd

with open(jail_file, 'w') as f:
    f.write(content)

print("  Секция [sshd] успешно обновлена")
PYEOF

    if [ $? -ne 0 ]; then
        fail "Ошибка при обновлении jail.local"
        exit 1
    fi

    # Показываем итоговую секцию
    echo ""
    info "Итоговая секция [sshd] в jail.local:"
    echo ""
    python3 -c "
import re
with open('$JAIL_LOCAL') as f: c = f.read()
m = re.search(r'\[sshd\].*?(?=\n\[|\Z)', c, re.DOTALL)
if m:
    for line in m.group().splitlines()[:10]:
        print('    ' + line)
"
    echo ""

    # ── Запуск и включение ───────────────────────────────────
    section "Запуск Fail2ban"

    systemctl enable fail2ban > /dev/null 2>&1
    systemctl restart fail2ban

    sleep 2

    if systemctl is-active --quiet fail2ban; then
        ok "Fail2ban запущен и добавлен в автозагрузку"
    else
        fail "Fail2ban не запустился — проверь: journalctl -u fail2ban -n 30"
        exit 1
    fi

    # ── Статус ───────────────────────────────────────────────
    section "Статус Fail2ban"

    echo ""
    fail2ban-client status sshd 2>/dev/null \
        || warn "jail sshd ещё инициализируется — подожди ~10 сек и проверь вручную"
    echo ""

    # ── Итог ─────────────────────────────────────────────────
    section "Готово"
    ok "Fail2ban установлен и настроен"
    echo ""
    info "Полезные команды:"
    echo ""
    echo -e "    ${CYAN}# Статус jail SSH:${NC}"
    echo "    fail2ban-client status sshd"
    echo ""
    echo -e "    ${CYAN}# Разбанить IP:${NC}"
    echo "    fail2ban-client set sshd unbanip <IP>"
    echo ""
    echo -e "    ${CYAN}# Журнал:${NC}"
    echo "    tail -f /var/log/fail2ban.log"
    echo ""
    if [ -n "${JAIL_BAK:-}" ]; then
        echo -e "    ${CYAN}# Откат:${NC}"
        echo "    cp $JAIL_BAK $JAIL_LOCAL && systemctl restart fail2ban"
        echo ""
    fi
}

# =============================================================
# Функция 3-5: sysctl настройка
# =============================================================
run_sysctl_setup() {
    local CHOICE="$1"
    local SERVER_TYPE="$2"
    local CONFIG_FILE="$3"

    if [ ! -f "$CONFIG_FILE" ]; then
        fail "Файл конфига не найден: $CONFIG_FILE"
        exit 1
    fi

    # ── Предварительные проверки ─────────────────────────────
    section "Предварительные проверки"

    ERRORS=0
    WARNINGS=0

    KERNEL=$(uname -r)
    MAJOR=$(echo "$KERNEL" | cut -d. -f1)
    MINOR=$(echo "$KERNEL" | cut -d. -f2)
    ok "Ядро: Linux $KERNEL"

    if [ "$MAJOR" -lt 4 ] || ([ "$MAJOR" -eq 4 ] && [ "$MINOR" -lt 9 ]); then
        fail "Ядро слишком старое (< 4.9), BBR не поддерживается"
        ERRORS=$((ERRORS+1))
    fi

    if modinfo tcp_bbr &>/dev/null 2>&1; then
        ok "Модуль tcp_bbr доступен"
    else
        fail "Модуль tcp_bbr не найден — BBR не будет работать"
        ERRORS=$((ERRORS+1))
    fi

    if modinfo nf_conntrack &>/dev/null 2>&1; then
        ok "Модуль nf_conntrack доступен"
    else
        warn "Модуль nf_conntrack не найден — conntrack параметры будут пропущены ядром"
        WARNINGS=$((WARNINGS+1))
    fi

    if command -v docker &>/dev/null; then
        if systemctl is-active --quiet docker; then
            ok "Docker запущен"
        else
            warn "Docker установлен но не запущен"
            WARNINGS=$((WARNINGS+1))
        fi
    else
        if [ "$CHOICE" -ne 3 ]; then
            warn "Docker не найден — для панели и бота он нужен"
            WARNINGS=$((WARNINGS+1))
        fi
    fi

    if [ "$CHOICE" -eq 3 ]; then
        IFACE_COUNT=$(ip -o link show | grep -vc 'lo\|docker\|veth\|tun\|wg')
        if [ "$IFACE_COUNT" -gt 1 ]; then
            warn "Несколько сетевых интерфейсов — проверь маршрутизацию после применения"
            WARNINGS=$((WARNINGS+1))
        fi
    fi

    if [ -f "$SYSCTL_FILE" ]; then
        warn "Уже есть $SYSCTL_FILE — будет сделан бэкап"
        WARNINGS=$((WARNINGS+1))
    fi

    echo ""
    if [ "$ERRORS" -gt 0 ]; then
        fail "Найдено критических ошибок: $ERRORS — установка прервана"
        info "Исправь ошибки выше и запусти снова"
        exit 1
    fi

    [ "$WARNINGS" -gt 0 ] && warn "Найдено предупреждений: $WARNINGS (не критично, можно продолжать)"

    # ── Подтверждение ────────────────────────────────────────
    section "Подтверждение"
    echo -e "  Сервер:  ${BOLD}$SERVER_TYPE${NC}"
    echo -e "  Конфиг:  ${BOLD}$CONFIG_FILE${NC}"
    echo -e "  Куда:    ${BOLD}$SYSCTL_FILE${NC}"
    echo ""
    read -rp "  Продолжить установку? [y/N]: " CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        info "Отменено пользователем"
        exit 0
    fi

    # ── Загрузка модулей ─────────────────────────────────────
    section "Загрузка модулей"

    if modprobe tcp_bbr 2>/dev/null; then
        ok "tcp_bbr загружен"
    else
        warn "tcp_bbr не удалось загрузить (возможно уже встроен в ядро)"
    fi

    if modprobe nf_conntrack 2>/dev/null; then
        ok "nf_conntrack загружен"
    else
        warn "nf_conntrack не удалось загрузить"
    fi

    MODULES_FILE="/etc/modules-load.d/sysctl-custom.conf"
    printf "tcp_bbr\nnf_conntrack\n" > "$MODULES_FILE"
    ok "Модули добавлены в автозагрузку: $MODULES_FILE"

    # ── Бэкап и установка ────────────────────────────────────
    section "Бэкап и установка"

    if [ -f "$SYSCTL_FILE" ]; then
        cp "$SYSCTL_FILE" "$BACKUP_FILE"
        ok "Бэкап сохранён: $BACKUP_FILE"
    fi

    cp "$CONFIG_FILE" "$SYSCTL_FILE"
    ok "Конфиг скопирован в $SYSCTL_FILE"

    info "Применяю параметры..."
    APPLY_OUTPUT=$(sysctl --system 2>&1)
    APPLY_ERRORS=$(echo "$APPLY_OUTPUT" | grep -i "error\|invalid\|unknown\|cannot" | grep -v "icmp_ignore_bogus_error_responses" || true)

    if [ -z "$APPLY_ERRORS" ]; then
        ok "Все параметры применены без ошибок"
    else
        warn "При применении были предупреждения:"
        echo "$APPLY_ERRORS" | while IFS= read -r line; do
            echo "     $line"
        done
    fi

    # ── Проверка ─────────────────────────────────────────────
    section "Проверка результата"

    check_param() {
        local key="$1"
        local expected="$2"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        if [ "$actual" = "$expected" ]; then
            ok "$key = $actual"
        elif [ "$actual" = "N/A" ]; then
            warn "$key — параметр недоступен на этом ядре"
        else
            warn "$key = $actual (ожидалось: $expected)"
        fi
    }

    check_param "net.ipv4.ip_forward" "1"
    check_param "net.ipv4.tcp_congestion_control" "bbr"
    check_param "net.core.default_qdisc" "fq"
    check_param "net.ipv4.tcp_syncookies" "1"
    check_param "kernel.randomize_va_space" "2"

    if [ "$CHOICE" -eq 3 ]; then
        check_param "net.netfilter.nf_conntrack_max" "1048576"
        check_param "net.core.somaxconn" "32768"
        check_param "net.core.rmem_max" "67108864"
        check_param "net.ipv4.tcp_ecn" "2"
    fi

    if [ "$CHOICE" -eq 4 ] || [ "$CHOICE" -eq 5 ]; then
        check_param "vm.dirty_background_ratio" "5"
        check_param "vm.dirty_ratio" "10"
    fi

    # ── Итог ─────────────────────────────────────────────────
    section "Готово"
    ok "Конфиг ${BOLD}$SERVER_TYPE${NC} успешно установлен"
    echo ""
    info "Для отката к дефолтным настройкам:"
    echo ""
    if [ -f "$BACKUP_FILE" ]; then
        echo -e "    ${CYAN}# Восстановить предыдущий конфиг:${NC}"
        echo "    cp $BACKUP_FILE $SYSCTL_FILE && sysctl --system"
    else
        echo -e "    ${CYAN}# Удалить конфиг и перезагрузиться:${NC}"
        echo "    rm $SYSCTL_FILE && reboot"
    fi
    echo ""
}

# =============================================================
# Главное меню
# =============================================================

show_menu() {
    clear
    echo -e "${BOLD}"
    echo "  ┌──────────────────────────────────────────────┐"
    echo "  │           VPS Setup Tool  v1.2               │"
    echo "  │  Первый запуск · Fail2ban · sysctl · WARP    │"
    echo "  └──────────────────────────────────────────────┘"
    echo -e "${NC}"

    section "Выбери действие"
    echo "  Что нужно сделать?"
    echo ""
    echo -e "  ${BOLD}1)${NC} Базовая настройка VPS    — пользователь, SSH, UFW"
    echo -e "  ${BOLD}2)${NC} Установка Fail2ban        — защита SSH от брутфорса"
    echo -e "  ${BOLD}3)${NC} sysctl: VPN нода          — Xray VLESS REALITY XTLS Vision"
    echo -e "  ${BOLD}4)${NC} sysctl: Remnawave панель  — Docker + Caddy + PostgreSQL"
    echo -e "  ${BOLD}5)${NC} sysctl: Telegram бот      — Docker + веб страница + PostgreSQL"
    echo -e "  ${BOLD}6)${NC} Установка Remnanode       — Xray нода для Remnawave"
    echo -e "  ${BOLD}7)${NC} Установка Caddy Selfsteal — реверс-прокси для REALITY"
    echo -e "  ${BOLD}8)${NC} Установка WARP            — Cloudflare WARP туннель"
    echo ""
    echo -e "  ${BOLD}0)${NC} Выход"
    echo ""
    read -rp "  Введи номер [0-8]: " CHOICE
}

while true; do
    show_menu

    case "$CHOICE" in
        0)
            info "Выход. До свидания!"
            echo ""
            exit 0
            ;;
        1)
            run_initial_setup
            ;;
        2)
            run_fail2ban_setup
            ;;
        3)
            check_configs_dir
            run_sysctl_setup 3 "VPN нода" "$CONFIGS_DIR/vpn-node.conf"
            ;;
        4)
            check_configs_dir
            run_sysctl_setup 4 "Remnawave панель" "$CONFIGS_DIR/panel.conf"
            ;;
        5)
            check_configs_dir
            run_sysctl_setup 5 "Telegram бот" "$CONFIGS_DIR/bot.conf"
            ;;
        6)
            section "Установка Remnanode"
            info "Запускаю установщик Remnanode..."
            echo ""
            bash <(curl -Ls https://github.com/DigneZzZ/remnawave-scripts/raw/main/remnanode.sh) @ install
            ;;
        7)
            section "Установка Caddy Selfsteal"
            info "Запускаю установщик Caddy Selfsteal..."
            echo ""
            bash <(curl -Ls https://github.com/DigneZzZ/remnawave-scripts/raw/main/selfsteal.sh) @ install
            ;;
        8)
            section "Установка WARP"
            info "Запускаю установщик WARP..."
            echo ""
            bash <(curl -sL https://github.com/DigneZzZ/remnawave-scripts/raw/main/wtm.sh) install-warp
            ;;
        *)
            warn "Неверный выбор. Попробуй снова."
            ;;
    esac

    echo ""
    read -rp "  Нажми Enter чтобы вернуться в меню..."
done
