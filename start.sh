#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"
if [[ -f "${ENV_FILE}" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "${ENV_FILE}"
    set +a
fi

NFQWS_ENGINE="${NFQWS_ENGINE:-1}"
QUEUE_NUM="${QUEUE_NUM:-29}"
NFQWS_TRACE="${NFQWS_TRACE:-1}"
NFQWS_FAKE_SNI="${NFQWS_FAKE_SNI:-dzen.ru}"
NFQWS_TCP_PORTS="${NFQWS_TCP_PORTS:-80,443,5222,5242}"
NFQWS_UDP_PORTS="${NFQWS_UDP_PORTS:-443,3478,590:65535}"
NFQWS2_TCP_PKT_OUT="${NFQWS2_TCP_PKT_OUT:-20}"
NFQWS2_TCP_PKT_IN="${NFQWS2_TCP_PKT_IN:-10}"
NFQWS2_UDP_PKT_OUT="${NFQWS2_UDP_PKT_OUT:-6}"
NFQWS2_UDP_PKT_IN="${NFQWS2_UDP_PKT_IN:-4}"
NFQWS2_UID="${NFQWS2_UID:-0}"
NFQWS2_GID="${NFQWS2_GID:-0}"
LOG_MAX_BYTES="${LOG_MAX_BYTES:-209715200}"

NFQWS1_BIN="${NFQWS1_BIN:-${SCRIPT_DIR}/vendor/zapret1/nfq/nfqws}"
NFQWS2_ROOT="${NFQWS2_ROOT:-${SCRIPT_DIR}/vendor/zapret2}"
NFQWS2_BIN="${NFQWS2_BIN:-${NFQWS2_ROOT}/nfq2/nfqws2}"
NFQWS2_RUNTIME_ROOT="${NFQWS2_RUNTIME_ROOT:-/run/3b-nfqws2-runtime}"
NFQWS_FWMARK="0x40000000/0x40000000"
NFQWS_FWMARK_VALUE="0x40000000"
OUT_CHAIN="THREEB_NFQWS_OUT"
IN_CHAIN="THREEB_NFQWS_IN"

LOG_DIR="${SCRIPT_DIR}/logs"
PROFILE_LOG_DIR="${LOG_DIR}/profiles"
LOG_FILE="${LOG_DIR}/nfqws.log"
DEBUG_LOG="${LOG_DIR}/nfqws-debug.log"
PID_FILE="/run/3b-nfqws.pid"
MAINTAINER_PID_FILE="/run/3b-log-maintainer.pid"
ROUTER_PID_FILE="/run/3b-log-router.pid"
mkdir -p "${PROFILE_LOG_DIR}"

die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }

[[ "${NFQWS_ENGINE}" == "1" || "${NFQWS_ENGINE}" == "2" ]] || die "NFQWS_ENGINE должен быть 1 или 2"
[[ "${QUEUE_NUM}" =~ ^[0-9]+$ ]] && (( QUEUE_NUM <= 65535 )) || die "некорректный QUEUE_NUM"
[[ "${NFQWS_TRACE}" == "0" || "${NFQWS_TRACE}" == "1" ]] || die "NFQWS_TRACE должен быть 0 или 1"
[[ "${NFQWS_FAKE_SNI}" =~ ^[A-Za-z0-9.-]+$ ]] || die "некорректный NFQWS_FAKE_SNI"
[[ "${NFQWS2_UID}" =~ ^[0-9]+$ && "${NFQWS2_GID}" =~ ^[0-9]+$ ]] || die "NFQWS2_UID и NFQWS2_GID должны быть числами"
command -v sudo >/dev/null || die "не найден sudo"
command -v iptables >/dev/null || die "не найден iptables"

if [[ "${NFQWS_ENGINE}" == "1" ]]; then
    NFQWS_BIN="${NFQWS1_BIN}"
    STRATEGIES_DIR="${NFQWS1_STRATEGIES_DIR:-${SCRIPT_DIR}/strategies}"
else
    NFQWS_BIN="${NFQWS2_BIN}"
    STRATEGIES_DIR="${NFQWS2_STRATEGIES_DIR:-${SCRIPT_DIR}/strategies2}"
    [[ -r "${NFQWS2_ROOT}/lua/zapret-lib.lua" && -r "${NFQWS2_ROOT}/lua/zapret-antidpi.lua" ]] || die "не найдены Lua-библиотеки nfqws2"
    if (( NFQWS2_UID != 0 )); then
        command -v getcap >/dev/null || die "NFQWS2_UID=${NFQWS2_UID}, но getcap не установлен; используйте NFQWS2_UID=0 и NFQWS2_GID=0"
        nfqws2_caps="$(getcap "${NFQWS_BIN}" 2>/dev/null || true)"
        [[ "${nfqws2_caps}" == *cap_net_admin* ]] || die "nfqws2 сбросит права до UID=${NFQWS2_UID} без CAP_NET_ADMIN; задайте NFQWS2_UID=0 и NFQWS2_GID=0"
    fi
fi
[[ -x "${NFQWS_BIN}" ]] || die "не найден исполняемый файл ${NFQWS_BIN}"

mapfile -t CONFIG_FILES < <(find "${STRATEGIES_DIR}" -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null | LC_ALL=C sort)
(( ${#CONFIG_FILES[@]} > 0 )) || die "нет активных стратегий в ${STRATEGIES_DIR}; скопируйте нужный .conf.example в .conf"

helper_stop() {
    local pid_file="$1" pid=""
    if sudo test -f "${pid_file}"; then
        pid="$(sudo cat "${pid_file}" 2>/dev/null || true)"
        [[ "${pid}" =~ ^[0-9]+$ ]] && sudo kill "${pid}" 2>/dev/null || true
        sudo rm -f "${pid_file}"
    fi
}

helper_start() {
    local script="$1" pid_file="$2"
    shift 2
    helper_stop "${pid_file}"
    sudo nohup "${script}" "${pid_file}" "$@" >/dev/null 2>&1 &
}

stop_managed_nfqws() {
    local pid="" comm=""
    if sudo test -f "${PID_FILE}"; then pid="$(sudo cat "${PID_FILE}" 2>/dev/null || true)"; fi
    if [[ "${pid}" =~ ^[0-9]+$ ]] && sudo kill -0 "${pid}" 2>/dev/null; then
        comm="$(ps -p "${pid}" -o comm= 2>/dev/null | xargs || true)"
        if [[ "${comm}" == "nfqws" || "${comm}" == "nfqws2" ]]; then
            sudo kill "${pid}" 2>/dev/null || true
            for _ in {1..20}; do sudo kill -0 "${pid}" 2>/dev/null || break; sleep 0.1; done
        fi
    fi
    sudo rm -f "${PID_FILE}"
}

remove_hook() {
    local builtin="$1" chain="$2"
    while sudo iptables -t mangle -C "${builtin}" -j "${chain}" 2>/dev/null; do
        sudo iptables -t mangle -D "${builtin}" -j "${chain}" || break
    done
}

remove_firewall() {
    remove_hook OUTPUT "${OUT_CHAIN}"
    remove_hook INPUT "${IN_CHAIN}"
    sudo iptables -t mangle -F "${OUT_CHAIN}" 2>/dev/null || true
    sudo iptables -t mangle -X "${OUT_CHAIN}" 2>/dev/null || true
    sudo iptables -t mangle -F "${IN_CHAIN}" 2>/dev/null || true
    sudo iptables -t mangle -X "${IN_CHAIN}" 2>/dev/null || true
    remove_hook OUTPUT THREEB_NFQWS
    sudo iptables -t mangle -F THREEB_NFQWS 2>/dev/null || true
    sudo iptables -t mangle -X THREEB_NFQWS 2>/dev/null || true
}

remove_legacy_direct_rules() {
    local rule
    while IFS= read -r rule; do
        if [[ "${rule}" == -A\ OUTPUT* && "${rule}" == *"-j NFQUEUE"* && "${rule}" == *"--queue-num ${QUEUE_NUM}"* ]]; then
            read -r -a args <<< "${rule}"
            args[0]="-D"
            sudo iptables -t mangle "${args[@]}" || true
        fi
    done < <(sudo iptables -t mangle -S OUTPUT)
}

FAIL_CLEANUP=1
TEMP_CONFIG=""
on_exit() {
    local rc=$?
    [[ -n "${TEMP_CONFIG}" && -f "${TEMP_CONFIG}" ]] && rm -f "${TEMP_CONFIG}"
    if (( rc != 0 && FAIL_CLEANUP == 1 )); then
        printf 'Запуск не завершён, удаляю добавленные правила.\n' >&2
        remove_firewall || true
    fi
}
trap on_exit EXIT

stop_managed_nfqws
helper_stop "${ROUTER_PID_FILE}"
remove_firewall
remove_legacy_direct_rules

if [[ "${NFQWS_ENGINE}" == "2" ]]; then
    # nfqws2 drops root before loading Lua/lists. Stage runtime assets outside a
    # potentially mode-700 home directory while keeping the source tree private.
    sudo install -d -m 0755 \
        "${NFQWS2_RUNTIME_ROOT}" \
        "${NFQWS2_RUNTIME_ROOT}/lua" \
        "${NFQWS2_RUNTIME_ROOT}/hostlists" \
        "${NFQWS2_RUNTIME_ROOT}/ipsets" \
        "${NFQWS2_RUNTIME_ROOT}/files/fake"
    sudo cp -a "${NFQWS2_ROOT}/lua/." "${NFQWS2_RUNTIME_ROOT}/lua/"
    sudo cp -a "${SCRIPT_DIR}/hostlists/." "${NFQWS2_RUNTIME_ROOT}/hostlists/"
    sudo cp -a "${SCRIPT_DIR}/ipsets/." "${NFQWS2_RUNTIME_ROOT}/ipsets/"
    sudo cp -a "${SCRIPT_DIR}/files/fake/." "${NFQWS2_RUNTIME_ROOT}/files/fake/"
    sudo chmod -R a+rX "${NFQWS2_RUNTIME_ROOT}"
fi

TEMP_CONFIG="$(mktemp /tmp/3b_nfqws_XXXXXX.conf)"
{
    printf '%s\n' "--qnum=${QUEUE_NUM}" "--pidfile=${PID_FILE}"
    if [[ "${NFQWS_ENGINE}" == "1" ]]; then
        printf '%s\n' "--dpi-desync-fwmark=${NFQWS_FWMARK_VALUE}"
    else
        printf '%s\n' "--fwmark=${NFQWS_FWMARK_VALUE}" "--uid=${NFQWS2_UID}:${NFQWS2_GID}"
    fi
    [[ "${NFQWS_TRACE}" == "1" ]] && printf '%s\n' '--debug=1' || printf '%s\n' '--daemon'
    if [[ "${NFQWS_ENGINE}" == "2" ]]; then
        printf '%s\n' \
            "--chdir=${NFQWS2_RUNTIME_ROOT}" \
            "--lua-init=@${NFQWS2_RUNTIME_ROOT}/lua/zapret-lib.lua" \
            "--lua-init=@${NFQWS2_RUNTIME_ROOT}/lua/zapret-antidpi.lua" \
            "--lua-init=@${NFQWS2_RUNTIME_ROOT}/lua/zapret-auto.lua"
    fi
} > "${TEMP_CONFIG}"

strategy_count=0
for config_file in "${CONFIG_FILES[@]}"; do
    strategy_name="$(basename "${config_file}" .conf)"
    ((strategy_count += 1))
    printf '\n# Strategy: %s\n' "${strategy_name}" >> "${TEMP_CONFIG}"
    first_option="$(awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ { next } { print; exit }' "${config_file}")"
    if (( strategy_count == 1 )); then
        # nfqws2 already has the first user profile before the first --new.
        # Keeping that first delimiter would create an empty catch-all profile.
        awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ { next } !seen { seen=1; if ($0 ~ /^--new=/) { sub(/^--new=/,"--name="); print; next } if ($0 == "--new") next } { print }' "${config_file}" >> "${TEMP_CONFIG}"
    else
        [[ "${first_option}" =~ ^--new(=.*)?$ ]] || printf '%s\n' "--new=${strategy_name}" >> "${TEMP_CONFIG}"
        awk '/^[[:space:]]*#/ || /^[[:space:]]*$/ { next } { print }' "${config_file}" >> "${TEMP_CONFIG}"
    fi
done

sed -i -E -e "s/sni=<FAKE_SNI>/sni=${NFQWS_FAKE_SNI}/g" -e "s/rndsni/sni=${NFQWS_FAKE_SNI}/g" "${TEMP_CONFIG}"

# Keep the exact assembled config (without secrets) so a running profile can
# be diagnosed after the temporary @config file is removed.
EFFECTIVE_CONFIG="${LOG_DIR}/nfqws-effective.conf"
cp "${TEMP_CONFIG}" "${EFFECTIVE_CONFIG}"
chmod 0644 "${EFFECTIVE_CONFIG}"

while IFS= read -r referenced; do
    referenced="${referenced#@}"
    [[ "${referenced}" = /* ]] || referenced="${SCRIPT_DIR}/${referenced#./}"
    [[ -f "${referenced}" ]] || die "файл из конфигурации отсутствует: ${referenced}"
done < <(sed -nE 's/.*--(hostlist|ipset)=([^[:space:]]+).*/\2/p' "${TEMP_CONFIG}" | tr -d '"')

VALIDATION_CONFIG="$(mktemp /tmp/3b_nfqws_validate_XXXXXX.conf)"
{
    # Keep validation-only global flags before the first profile. Some nfqws2
    # builds treat global options placed after --new as profile-local and may
    # otherwise attempt to open NFQUEUE during what should be a dry run.
    printf '%s\n' '--dry-run' '--intercept=0'
    sed -E '/^--(debug|daemon|pidfile|dry-run|intercept)/d' "${TEMP_CONFIG}"
} > "${VALIDATION_CONFIG}"
"${NFQWS_BIN}" "@${VALIDATION_CONFIG}" >/dev/null 2>&1 || {
    "${NFQWS_BIN}" "@${VALIDATION_CONFIG}" || true
    rm -f "${VALIDATION_CONFIG}"
    die "nfqws${NFQWS_ENGINE} отклонил собранную конфигурацию"
}
rm -f "${VALIDATION_CONFIG}"

sudo iptables -t mangle -N "${OUT_CHAIN}"
sudo iptables -t mangle -A "${OUT_CHAIN}" -m mark --mark "${NFQWS_FWMARK}" -j RETURN
for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do sudo iptables -t mangle -A "${OUT_CHAIN}" -d "${net}" -j RETURN; done
sudo iptables -t mangle -A "${OUT_CHAIN}" -p tcp --sport 22 -j RETURN
sudo iptables -t mangle -A "${OUT_CHAIN}" -p tcp --dport 22 -j RETURN
sudo iptables -t mangle -A "${OUT_CHAIN}" -p tcp --dport 53 -j RETURN
sudo iptables -t mangle -A "${OUT_CHAIN}" -p udp --dport 53 -j RETURN

if [[ "${NFQWS_ENGINE}" == "2" ]]; then
    sudo iptables -t mangle -A "${OUT_CHAIN}" -p tcp -m multiport --dports "${NFQWS_TCP_PORTS}" -m connbytes --connbytes "1:${NFQWS2_TCP_PKT_OUT}" --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
    sudo iptables -t mangle -A "${OUT_CHAIN}" -p udp -m multiport --dports "${NFQWS_UDP_PORTS}" -m connbytes --connbytes "1:${NFQWS2_UDP_PKT_OUT}" --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
    sudo iptables -t mangle -N "${IN_CHAIN}"
    sudo iptables -t mangle -A "${IN_CHAIN}" -p tcp -m multiport --sports "${NFQWS_TCP_PORTS}" -m connbytes --connbytes "1:${NFQWS2_TCP_PKT_IN}" --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
    sudo iptables -t mangle -A "${IN_CHAIN}" -p udp -m multiport --sports "${NFQWS_UDP_PORTS}" -m connbytes --connbytes "1:${NFQWS2_UDP_PKT_IN}" --connbytes-dir reply --connbytes-mode packets -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
    sudo iptables -t mangle -I INPUT 1 -j "${IN_CHAIN}"
else
    sudo iptables -t mangle -A "${OUT_CHAIN}" -p tcp -m multiport --dports "${NFQWS_TCP_PORTS}" -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
    sudo iptables -t mangle -A "${OUT_CHAIN}" -p udp -m multiport --dports "${NFQWS_UDP_PORTS}" -j NFQUEUE --queue-num "${QUEUE_NUM}" --queue-bypass
fi
sudo iptables -t mangle -I OUTPUT 1 -j "${OUT_CHAIN}"

sudo touch "${LOG_FILE}" "${DEBUG_LOG}"
sudo chmod 0644 "${LOG_FILE}" "${DEBUG_LOG}"
helper_start "${SCRIPT_DIR}/scripts/log-maintainer.sh" "${MAINTAINER_PID_FILE}" "${LOG_DIR}" "${LOG_MAX_BYTES}"
if [[ "${NFQWS_TRACE}" == "1" ]]; then
    sudo truncate -s 0 "${DEBUG_LOG}"
    sudo nohup "${NFQWS_BIN}" "@${EFFECTIVE_CONFIG}" >> "${DEBUG_LOG}" 2>&1 &
else
    sudo "${NFQWS_BIN}" "@${EFFECTIVE_CONFIG}" >> "${LOG_FILE}" 2>&1
fi

actual_pid=""
for _ in {1..40}; do
    if sudo test -f "${PID_FILE}"; then actual_pid="$(sudo cat "${PID_FILE}" 2>/dev/null || true)"; fi
    [[ "${actual_pid}" =~ ^[0-9]+$ ]] && sudo kill -0 "${actual_pid}" 2>/dev/null && break
    sleep 0.1
done
[[ "${actual_pid}" =~ ^[0-9]+$ ]] && sudo kill -0 "${actual_pid}" 2>/dev/null || die "nfqws${NFQWS_ENGINE} не запустился; проверьте ${DEBUG_LOG}"

FAIL_CLEANUP=0
printf '3B запущен: engine=nfqws%s, PID=%s, queue=%s, strategies=%s\n' "${NFQWS_ENGINE}" "${actual_pid}" "${QUEUE_NUM}" "${#CONFIG_FILES[@]}"
printf 'Лог: %s\n' "$([[ "${NFQWS_TRACE}" == "1" ]] && printf '%s' "${DEBUG_LOG}" || printf '%s' "${LOG_FILE}")"
