#!/bin/bash
# ============================================================================
# 3B DPI Unblock System
# Advanced DPI bypass system with modular configuration
# ============================================================================

# --- Конфигурация (меняйте здесь) ---
NFQWS_BIN="./nfqws"
QUEUE_NUM=29
LOG_MAX_BYTES=209715200
PID_FILE="/run/3b-nfqws.pid"
LOG_MAINTAINER_PID_FILE="/run/3b-log-maintainer.pid"
LOG_ROUTER_PID_FILE="/run/3b-log-router.pid"
STRATEGIES_DIR="./strategies"
HOSTLISTS_DIR="./hostlists"
NFQWS_TCP_PORTS="80,443,5222,5242"
NFQWS_UDP_PORTS="443,3478,590:65535"
NFQWS_FWMARK="0x40000000/0x40000000"
IPTABLES_CHAIN="THREEB_NFQWS"
NFQWS_TRACE="${NFQWS_TRACE:-1}"
NFQWS_FAKE_SNI="${NFQWS_FAKE_SNI:-dzen.ru}"

# --- Не менять ниже этой линии ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}" || exit 1
LOG_DIR="${SCRIPT_DIR}/logs"
PROFILE_LOG_DIR="${LOG_DIR}/profiles"
LOG_FILE="${LOG_DIR}/nfqws.log"
DEBUG_LOG="${LOG_DIR}/nfqws-debug.log"
PROFILE_MAP="${LOG_DIR}/profile-map.tsv"
mkdir -p "${PROFILE_LOG_DIR}"

start_helper() {
    local script_path="$1"
    local pid_file="$2"
    shift 2

    if sudo test -f "${pid_file}"; then
        local old_pid
        old_pid=$(sudo cat "${pid_file}" 2>/dev/null)
        if [[ "${old_pid}" =~ ^[0-9]+$ ]]; then
            sudo kill "${old_pid}" 2>/dev/null || true
        fi
        sudo rm -f "${pid_file}"
    fi

    sudo nohup "${script_path}" "${pid_file}" "$@" >/dev/null 2>&1 &
}

stop_helper() {
    local pid_file="$1"
    if sudo test -f "${pid_file}"; then
        local helper_pid
        helper_pid=$(sudo cat "${pid_file}" 2>/dev/null)
        if [[ "${helper_pid}" =~ ^[0-9]+$ ]]; then
            sudo kill "${helper_pid}" 2>/dev/null || true
        fi
        sudo rm -f "${pid_file}"
    fi
}

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

stop_helper "${LOG_ROUTER_PID_FILE}"
start_helper "${SCRIPT_DIR}/scripts/log-maintainer.sh" \
    "${LOG_MAINTAINER_PID_FILE}" "${LOG_DIR}" "${LOG_MAX_BYTES}"

clear
echo "==============================================="
echo "          3B DPI BYPASS SYSTEM v2.0"
echo "==============================================="
echo "Queue: ${QUEUE_NUM}"
echo "Log: ${LOG_FILE}"
echo "Trace: ${NFQWS_TRACE}"
echo "Fake SNI: ${NFQWS_FAKE_SNI}"
echo "Стратегии: ${ACTIVE_STRATEGIES}"
echo "==============================================="
echo ""

# ============================================================================
# 1. Остановка запущенных процессов
# ============================================================================
echo "[1/4] Остановка предыдущих процессов"
echo "Проверка PID-файла ${PID_FILE}..."

PREVIOUS_PID=""
if sudo test -f "${PID_FILE}"; then
    PREVIOUS_PID=$(sudo cat "${PID_FILE}" 2>/dev/null)
fi

if [[ "${PREVIOUS_PID}" =~ ^[0-9]+$ ]] && sudo kill -0 "${PREVIOUS_PID}" 2>/dev/null; then
    PROCESS_NAME=$(ps -p "${PREVIOUS_PID}" -o comm= 2>/dev/null | xargs)
    if [ "${PROCESS_NAME}" = "nfqws" ]; then
        sudo kill "${PREVIOUS_PID}"
        sleep 2
        echo "Процесс ${PREVIOUS_PID} остановлен"
    else
        echo "PID ${PREVIOUS_PID} принадлежит ${PROCESS_NAME}, пропускаем"
    fi
else
    echo "Управляемый процесс не найден"
fi
sudo rm -f "${PID_FILE}" 2>/dev/null

echo "Очистка временных конфигов..."
sudo rm -f /tmp/3b_nfqws_*.conf 2>/dev/null
echo "Временные конфиги удалены"
echo ""

# ============================================================================
# 2. Подготовка собственной цепочки iptables
# ============================================================================
echo "[2/4] Подготовка сетевых правил"

LEGACY_RULES_REMOVED=0
while IFS= read -r legacy_rule; do
    if [[ "${legacy_rule}" == *"-j NFQUEUE"* ]] && \
       [[ "${legacy_rule}" == *"--queue-num ${QUEUE_NUM}"* ]]; then
        read -r -a legacy_args <<< "${legacy_rule}"
        legacy_args[0]="-D"
        if sudo iptables -t mangle "${legacy_args[@]}"; then
            LEGACY_RULES_REMOVED=$((LEGACY_RULES_REMOVED + 1))
        fi
    fi
done < <(sudo iptables -t mangle -S OUTPUT)
echo "Удалено старых прямых правил NFQUEUE ${QUEUE_NUM}: ${LEGACY_RULES_REMOVED}"

if ! sudo iptables -t mangle -N "${IPTABLES_CHAIN}" 2>/dev/null; then
    sudo iptables -t mangle -F "${IPTABLES_CHAIN}" || exit 1
fi

if ! sudo iptables -t mangle -C OUTPUT -j "${IPTABLES_CHAIN}" 2>/dev/null; then
    sudo iptables -t mangle -I OUTPUT 1 -j "${IPTABLES_CHAIN}" || exit 1
fi

echo "Цепочка готова: ${IPTABLES_CHAIN}"
echo ""

# ============================================================================
# 3. Настройка правил трафика
# ============================================================================
echo "[3/4] Настройка перенаправления трафика"

echo "Добавление исключений..."

SSH_RULES=0
if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" -p tcp --sport 22 -j RETURN 2>/dev/null; then SSH_RULES=$((SSH_RULES + 1)); fi
if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" -p tcp --dport 22 -j RETURN 2>/dev/null; then SSH_RULES=$((SSH_RULES + 1)); fi
echo "Правила SSH: ${SSH_RULES}"

DNS_RULES=0
for proto in tcp udp; do
    if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" -p "${proto}" --sport 53 -j RETURN 2>/dev/null; then DNS_RULES=$((DNS_RULES + 1)); fi
    if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" -p "${proto}" --dport 53 -j RETURN 2>/dev/null; then DNS_RULES=$((DNS_RULES + 1)); fi
done
echo "Правила DNS: ${DNS_RULES}"

LOCAL_NETS="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
LOCAL_COUNT=0
for net in ${LOCAL_NETS}; do
    if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" -d "${net}" -j RETURN 2>/dev/null; then LOCAL_COUNT=$((LOCAL_COUNT + 1)); fi
done
echo "Локальные сети: ${LOCAL_COUNT}"

FWMARK_RULES=0
if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" \
    -m mark --mark "${NFQWS_FWMARK}" -j RETURN 2>/dev/null; then
    FWMARK_RULES=$((FWMARK_RULES + 1))
fi
echo "Исключения fwmark: ${FWMARK_RULES}"
if [ "${FWMARK_RULES}" -ne 1 ]; then
    echo "Ошибка: не удалось добавить исключение fwmark ${NFQWS_FWMARK}."
    exit 1
fi

MAIN_RULES=0
if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" \
    -p tcp -m multiport --dports "${NFQWS_TCP_PORTS}" \
    -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass; then
    MAIN_RULES=$((MAIN_RULES + 1))
fi

if sudo iptables -t mangle -A "${IPTABLES_CHAIN}" \
    -p udp -m multiport --dports "${NFQWS_UDP_PORTS}" \
    -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass; then
    MAIN_RULES=$((MAIN_RULES + 1))
fi
echo "Основные правила: ${MAIN_RULES}"
if [ "${MAIN_RULES}" -ne 2 ]; then
    echo "Ошибка: не удалось добавить правила NFQUEUE."
    echo "Проверьте поддержку модуля nfnetlink_queue."
    exit 1
fi

echo ""
echo "Текущее состояние цепочки ${IPTABLES_CHAIN}:"
sudo iptables -t mangle -L "${IPTABLES_CHAIN}" -n --line-numbers
echo ""

# ============================================================================
# 4. Создание конфига и запуск
# ============================================================================
echo "[4/4] Запуск системы"

TEMP_CONFIG=$(mktemp /tmp/3b_nfqws_XXXXXX.conf)
echo "Временный конфиг: ${TEMP_CONFIG}"

{
    echo "--qnum=${QUEUE_NUM}"
    echo "--pidfile=${PID_FILE}"
    if [ "${NFQWS_TRACE}" = "1" ]; then
        echo "--debug=1"
    else
        echo "--daemon"
    fi
} > "${TEMP_CONFIG}"

STRATEGY_COUNT=0
for strategy in ${ACTIVE_STRATEGIES}; do
    CONFIG_FILE="${STRATEGIES_DIR}/${strategy}.conf"

    if [ -f "${CONFIG_FILE}" ]; then
        STRATEGY_COUNT=$((STRATEGY_COUNT + 1))
        echo "" >> "${TEMP_CONFIG}"
        echo "# Strategy: ${strategy}" >> "${TEMP_CONFIG}"
        if [ "${STRATEGY_COUNT}" -gt 1 ]; then
            echo "--new" >> "${TEMP_CONFIG}"
        fi
        awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                if (first_option == "") {
                    first_option=1
                    if ($0 == "--new") next
                }
                print
            }
        ' "${CONFIG_FILE}" >> "${TEMP_CONFIG}"
        echo "Стратегия загружена: ${strategy}"
    fi
done

if [ "${STRATEGY_COUNT}" -eq 0 ]; then
    echo "Ошибка: ни одной стратегии не найдено."
    rm -f "${TEMP_CONFIG}"
    exit 1
fi

if [[ ! "${NFQWS_FAKE_SNI}" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "Ошибка: недопустимое значение NFQWS_FAKE_SNI=${NFQWS_FAKE_SNI}"
    rm -f "${TEMP_CONFIG}"
    exit 1
fi

sed -i -E \
    -e "s/sni=<FAKE_SNI>/sni=${NFQWS_FAKE_SNI}/g" \
    -e "s/rndsni/sni=${NFQWS_FAKE_SNI}/g" \
    -e "s/sni=[A-Za-z0-9.-]+/sni=${NFQWS_FAKE_SNI}/g" \
    "${TEMP_CONFIG}"

echo ""
echo "Предпросмотр:"
cat "${TEMP_CONFIG}"
echo ""

echo "Карта профилей:"
awk '
    function begin_profile() {
        if (!started) {
            profile=1
            started=1
            printf "\nПрофиль %d [%s]", profile, source
        }
    }
    /^# Strategy:/ { source=$0; sub(/^# Strategy:[[:space:]]*/, "", source) }
    /^--new$/ {
        if (started) profile++; else { profile=1; started=1 }
        printf "\nПрофиль %d [%s]", profile, source
    }
    /^--comment=/ { begin_profile(); printf " | %s", $0 }
    /^--filter-(tcp|udp|l7|l3)=/ || /^--(hostlist|hostlist-domains|ipset)=/ {
        begin_profile()
        printf "\n  %s", $0
    }
    END { print "" }
' "${TEMP_CONFIG}"
echo ""

awk '
    function register_profile() {
        if (!started) { profile=1; started=1 }
        if (!(profile in saved)) {
            print profile "\t" source
            saved[profile]=1
        }
    }
    /^# Strategy:/ { source=$0; sub(/^# Strategy:[[:space:]]*/, "", source) }
    /^--new$/ {
        if (started) profile++; else { profile=1; started=1 }
        register_profile()
    }
    /^--filter-(tcp|udp|l7|l3)=/ { register_profile() }
' "${TEMP_CONFIG}" > "${PROFILE_MAP}"

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

if [ "${NFQWS_TRACE}" = "1" ]; then
    sudo touch "${DEBUG_LOG}"
    sudo chmod 644 "${DEBUG_LOG}"
    sudo truncate -s 0 "${DEBUG_LOG}"
    while IFS= read -r -d '' profile_log; do
        sudo truncate -s 0 "${profile_log}"
    done < <(find "${PROFILE_LOG_DIR}" -type f -name '*.log' -print0 2>/dev/null)
    echo "Подробная трассировка: ${DEBUG_LOG}"
fi

if [ "${NFQWS_TRACE}" = "1" ]; then
    sudo nohup "${NFQWS_BIN}" "@${TEMP_CONFIG}" >> "${DEBUG_LOG}" 2>&1 &
else
    sudo "${NFQWS_BIN}" "@${TEMP_CONFIG}" >> "${LOG_FILE}" 2>&1
fi
sleep 3

# Проверка запуска
ACTUAL_PID=""
MAX_RETRIES=3
RETRY_COUNT=0

while [[ -z "${ACTUAL_PID}" && "${RETRY_COUNT}" -lt "${MAX_RETRIES}" ]]; do
    sleep 1
    if sudo test -f "${PID_FILE}"; then
        ACTUAL_PID=$(sudo cat "${PID_FILE}" 2>/dev/null)
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
done

if [[ "${ACTUAL_PID}" =~ ^[0-9]+$ ]] && sudo kill -0 "${ACTUAL_PID}" 2>/dev/null; then
    echo "nfqws запущен, PID: ${ACTUAL_PID}"
    if [ "${NFQWS_TRACE}" = "1" ]; then
        start_helper "${SCRIPT_DIR}/scripts/profile-log-router.sh" \
            "${LOG_ROUTER_PID_FILE}" "${DEBUG_LOG}" "${PROFILE_MAP}" "${PROFILE_LOG_DIR}"
        echo "Логи профилей: ${PROFILE_LOG_DIR}"
    fi
else
    echo "Ошибка: nfqws не запустился. Проверьте ${LOG_FILE}"
    exit 1
fi
