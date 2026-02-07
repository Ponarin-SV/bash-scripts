#!/usr/bin/env bash
# procwatch.sh — мониторинг процессов с аномальной нагрузкой на CPU
# Версия: 1.2

set -euo pipefail

# === КОНФИГУРАЦИЯ ===
LOG_DIR="/var/log/suspicious-processes"
THRESHOLD_CPU=70.0
THRESHOLD_TOTAL=300
MIN_PID=100
CACHE_FILE="/tmp/procwatch.cache"
MAX_CACHE_AGE=300

# === ИНИЦИАЛИЗАЦИЯ ===
mkdir -p "$LOG_DIR" 2>/dev/null || sudo mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR" 2>/dev/null || sudo chmod 755 "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_DIR/procwatch.log" 2>/dev/null
}

capture_process() {
    local pid="$1"
    local timestamp="$(date +%Y%m%d_%H%M%S)"
    local dump_dir="$LOG_DIR/dump_${pid}_${timestamp}"
    mkdir -p "$dump_dir" 2>/dev/null || sudo mkdir -p "$dump_dir"

    log "⚠️  Аномальный процесс: PID=$pid, CPU=$2%, CMD=$3"

    # 1. Аргументы запуска
    if [ -f "/proc/$pid/cmdline" ]; then
        tr '\0' ' ' < "/proc/$pid/cmdline" > "$dump_dir/cmdline.txt" 2>/dev/null || echo "[нет доступа]" > "$dump_dir/cmdline.txt"
    fi

    # 2. Рабочая директория
    if [ -L "/proc/$pid/cwd" ]; then
        ls -la "/proc/$pid/cwd" 2>/dev/null | awk '{print $NF}' > "$dump_dir/cwd.txt" || echo "[неизвестно]" > "$dump_dir/cwd.txt"
    fi

    # 3. Владелец
    ps -o user,group,etimes -p "$pid" > "$dump_dir/owner.txt" 2>/dev/null || echo "unknown" > "$dump_dir/owner.txt"

    # 4. Открытые файлы
    if command -v lsof >/dev/null 2>&1; then
        lsof -p "$pid" 2>/dev/null | head -50 > "$dump_dir/files.txt" || echo "[lsof недоступен]" > "$dump_dir/files.txt"
    else
        echo "lsof не установлен" > "$dump_dir/files.txt"
    fi

    # 5. Сетевые соединения
    ss -tpn 2>/dev/null | grep -w "$pid" > "$dump_dir/connections.txt" 2>/dev/null || echo "нет активных соединений" > "$dump_dir/connections.txt"

    # 6. Стек вызовов (требует root)
    if [ "$EUID" -eq 0 ] && [ -f "/proc/$pid/stack" ]; then
        cat "/proc/$pid/stack" > "$dump_dir/stack.txt" 2>/dev/null || echo "[недоступен]" > "$dump_dir/stack.txt"
    fi

    # 7. Дерево процессов
    if command -v pstree >/dev/null 2>&1; then
        pstree -aps "$pid" > "$dump_dir/pstree.txt" 2>/dev/null || echo "[pstree недоступен]" > "$dump_dir/pstree.txt"
    else
        echo "pstree не установлен" > "$dump_dir/pstree.txt"
    fi

    # 8. Проверка на майнер
    if grep -qiE "(stratum|pool|mine|xmrig|cpuminer|ethminer|cryptonight)" "$dump_dir/cmdline.txt" "$dump_dir/files.txt" "$dump_dir/connections.txt" 2>/dev/null; then
        log "🚨 ВНИМАНИЕ: Обнаружены сигнатуры криптомайнера в процессе $pid!"
        touch "$dump_dir/ALERT_MINER"
    fi

    log "💾 Дамп сохранён: $dump_dir"
    echo "$pid:$(date +%s)" >> "$CACHE_FILE"
}

# Очистка старого кэша
if [ -f "$CACHE_FILE" ]; then
    awk -v now="$(date +%s)" -v max_age="$MAX_CACHE_AGE" -F: '$2 > now - max_age' "$CACHE_FILE" > "${CACHE_FILE}.tmp" 2>/dev/null && mv "${CACHE_FILE}.tmp" "$CACHE_FILE" 2>/dev/null || true
fi

# Получаем топ-20 процессов по CPU
mapfile -t processes < <(ps -eo pid,pcpu,comm --sort=-%cpu | awk -v min_pid="$MIN_PID" -v thresh_cpu="$THRESHOLD_CPU" -v thresh_total="$THRESHOLD_TOTAL" '
    NR>1 {
        pid=$1; pcpu=$2; comm=$3
        if (pid < min_pid) next
        if (pcpu+0 >= thresh_cpu || pcpu+0 >= thresh_total) print pid":"pcpu":"comm
    }' | head -20)

for proc in "${processes[@]}"; do
    IFS=':' read -r pid pcpu comm <<< "$proc"

    # Пропустить, если уже логировали недавно
    if grep -q "^$pid:" "$CACHE_FILE" 2>/dev/null; then
        continue
    fi

    # Белый список
    case "$comm" in
        systemd|kworker|rcu_*|watchdog/*|migration/*) continue ;;
    esac

    capture_process "$pid" "$pcpu" "$comm"
done

# Ротация дампов старше 30 дней
find "$LOG_DIR" -type d -name "dump_*" -mtime +30 -exec rm -rf {} + 2>/dev/null || true

exit 0
