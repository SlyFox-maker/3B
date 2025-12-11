#!/bin/bash
# ============================================================================
# 3B DPI Unblock System
# Advanced DPI bypass system with modular configuration
# ============================================================================

# --- Конфигурация (меняйте здесь) ---
NFQWS_BIN="./nfqws"
QUEUE_NUM=29
LOG_FILE="/var/log/nfqws.log"
STRATEGIES_DIR="./strategies"
HOSTLISTS_DIR="./hostlists"

# --- Не менять ниже этой линии ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}" || exit 1

# ============================================================================
# Сканирование стратегий
# ============================================================================
echo "Поиск стратегий в ${STRATEGIES_DIR}/"
ACTIVE_STRATEGIES=""

if [ -d "${STRATEGIES_DIR}" ]; then
    for config_file in "${STRATEGIES_DIR}"/*.conf; do
        if [ -f "${config_file}" ]; then
            strategy_name=$(basename "${config_file}" .conf)
            ACTIVE_STRATEGIES="${ACTIVE_STRATEGIES} ${strategy_name}"
        fi
    done

    ACTIVE_STRATEGIES=$(echo "${ACTIVE_STRATEGIES}" | xargs)

    if [ -z "${ACTIVE_STRATEGIES}" ]; then
        echo "Нет доступных стратегий. Создайте хотя бы один .conf файл."
        exit 1
    fi
else
    echo "Папка стратегий не существует: ${STRATEGIES_DIR}/"
    exit 1
fi

clear
echo "==============================================="
echo "          3B DPI BYPASS SYSTEM v2.0"
echo "==============================================="
echo "Queue: ${QUEUE_NUM}"
echo "Log: ${LOG_FILE}"
echo "Стратегии: ${ACTIVE_STRATEGIES}"
echo "==============================================="
echo ""

# ============================================================================
# 1. Остановка запущенных процессов
# ============================================================================
echo "[1/4] Остановка предыдущих процессов"
echo "Поиск активных процессов nfqws..."

RUNNING_COUNT=$(pgrep -f "nfqws" 2>/dev/null | wc -l)

if [ "${RUNNING_COUNT}" -gt 0 ]; then
    echo "Найдено процессов: ${RUNNING_COUNT}"
    sudo pkill -f "nfqws" 2>/dev/null
    sleep 3
    echo "Процессы остановлены"
else
    echo "Активных процессов нет"
fi

echo "Очистка временных конфигов..."
sudo rm -f /tmp/3b_nfqws_*.conf 2>/dev/null
echo "Временные конфиги удалены"
echo ""

# ============================================================================
# 2. Очистка iptables
# ============================================================================
echo "[2/4] Очистка сетевых правил"

TABLES_CLEANED=0
for table in mangle raw; do
    echo "Очистка таблицы ${table}"

    if sudo iptables -t ${table} -F 2>/dev/null; then
        sudo iptables -t ${table} -X 2>/dev/null
        TABLES_CLEANED=$((TABLES_CLEANED + 1))
    fi

    if sudo ip6tables -t ${table} -F 2>/dev/null; then
        sudo ip6tables -t ${table} -X 2>/dev/null
        TABLES_CLEANED=$((TABLES_CLEANED + 1))
    fi
done

echo "Очищено таблиц: ${TABLES_CLEANED}"
echo ""

# ============================================================================
# 3. Настройка правил трафика
# ============================================================================
echo "[3/4] Настройка перенаправления трафика"

echo "Добавление исключений..."

SSH_RULES=0
if sudo iptables -t mangle -I OUTPUT -p tcp --sport 22 -j RETURN 2>/dev/null; then SSH_RULES=$((SSH_RULES + 1)); fi
if sudo iptables -t mangle -I OUTPUT -p tcp --dport 22 -j RETURN 2>/dev/null; then SSH_RULES=$((SSH_RULES + 1)); fi
echo "Правила SSH: ${SSH_RULES}"

DNS_RULES=0
for proto in tcp udp; do
    if sudo iptables -t mangle -I OUTPUT -p ${proto} --sport 53 -j RETURN 2>/dev/null; then DNS_RULES=$((DNS_RULES + 1)); fi
    if sudo iptables -t mangle -I OUTPUT -p ${proto} --dport 53 -j RETURN 2>/dev/null; then DNS_RULES=$((DNS_RULES + 1)); fi
done
echo "Правила DNS: ${DNS_RULES}"

LOCAL_NETS="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
LOCAL_COUNT=0
for net in ${LOCAL_NETS}; do
    if sudo iptables -t mangle -I OUTPUT -d ${net} -j RETURN 2>/dev/null; then LOCAL_COUNT=$((LOCAL_COUNT + 1)); fi
done
echo "Локальные сети: ${LOCAL_COUNT}"

MAIN_RULES=0
if sudo iptables -t mangle -A OUTPUT -p tcp -j NFQUEUE --queue-num ${QUEUE_NUM}; then MAIN_RULES=$((MAIN_RULES + 1)); fi
if sudo iptables -t mangle -A OUTPUT -p udp -j NFQUEUE --queue-num ${QUEUE_NUM}; then MAIN_RULES=$((MAIN_RULES + 1)); fi
echo "Основные правила: ${MAIN_RULES}"

echo ""
echo "Текущее состояние (iptables -t mangle -L OUTPUT):"
sudo iptables -t mangle -L OUTPUT -n --line-numbers | tail -15
echo ""

# ============================================================================
# 4. Создание конфига и запуск
# ============================================================================
echo "[4/4] Запуск системы"

TEMP_CONFIG=$(mktemp /tmp/3b_nfqws_XXXXXX.conf)
echo "Временный конфиг: ${TEMP_CONFIG}"

{
    echo "--qnum=${QUEUE_NUM}"
    echo "--daemon"
} > "${TEMP_CONFIG}"

STRATEGY_COUNT=0
for strategy in ${ACTIVE_STRATEGIES}; do
    CONFIG_FILE="${STRATEGIES_DIR}/${strategy}.conf"

    if [ -f "${CONFIG_FILE}" ]; then
        STRATEGY_COUNT=$((STRATEGY_COUNT + 1))
        echo "" >> "${TEMP_CONFIG}"
        echo "# Strategy: ${strategy}" >> "${TEMP_CONFIG}"
        grep -v '^#' "${CONFIG_FILE}" | grep -v '^$' >> "${TEMP_CONFIG}"
        echo "Стратегия загружена: ${strategy}"
    fi
done

if [ "${STRATEGY_COUNT}" -eq 0 ]; then
    echo "Ошибка: ни одной стратегии не найдено."
    rm -f "${TEMP_CONFIG}"
    exit 1
fi

echo ""
echo "Предпросмотр:"
cat "${TEMP_CONFIG}"
echo ""

echo "Проверка hostlist файлов..."

MISSING_FILES=0
while read -r line; do
    if [[ "${line}" =~ --hostlist= ]]; then
        hostlist_file=$(echo "${line}" | cut -d'=' -f2- | tr -d '"')
        if [[ ! -f "${hostlist_file}" ]]; then
            echo "Файл отсутствует: ${hostlist_file}"
            MISSING_FILES=$((MISSING_FILES + 1))
        else
            echo "Файл найден: ${hostlist_file}"
        fi
    fi
done < "${TEMP_CONFIG}"

if [ "${MISSING_FILES}" -gt 0 ]; then
    echo "Ошибки: отсутствуют hostlist файлы."
    rm -f "${TEMP_CONFIG}"
    exit 1
fi

echo "Запуск nfqws..."
sudo touch "${LOG_FILE}"
sudo chmod 644 "${LOG_FILE}"

sudo "${NFQWS_BIN}" "@${TEMP_CONFIG}" >> "${LOG_FILE}" 2>&1
sleep 3

# Проверка запуска
ACTUAL_PID=""
MAX_RETRIES=3
RETRY_COUNT=0

while [[ -z "${ACTUAL_PID}" && "${RETRY_COUNT}" -lt "${MAX_RETRIES}" ]]; do
    sleep 1
    ACTUAL_PID=$(pgrep -f "nfqws.*${QUEUE_NUM}" 2>/dev/null)
    RETRY_COUNT=$((RETRY_COUNT + 1))
done
