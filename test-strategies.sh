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
TEST_LEVEL="${STRATEGY_TEST_LEVEL:-standard}"
TEST_REPEATS="${STRATEGY_TEST_REPEATS:-3}"
TEST_BATCH="${STRATEGY_TEST_BATCH:-0}"
TEST_PARALLEL="${STRATEGY_TEST_PARALLEL:-0}"
TEST_IPV="${STRATEGY_TEST_IPV:-4}"
TEST_DOMAINS="${STRATEGY_TEST_DOMAINS:-}"
TEST_CURL_MAX_TIME="${STRATEGY_TEST_CURL_MAX_TIME:-3}"
TEST_IP_OVERRIDES="${STRATEGY_TEST_IP_OVERRIDES:-}"

die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
[[ "${NFQWS_ENGINE}" == "1" || "${NFQWS_ENGINE}" == "2" ]] || die "NFQWS_ENGINE должен быть 1 или 2"
[[ "${TEST_REPEATS}" =~ ^[1-9][0-9]*$ ]] || die "STRATEGY_TEST_REPEATS должен быть положительным числом"
[[ "${TEST_LEVEL}" == "quick" || "${TEST_LEVEL}" == "standard" || "${TEST_LEVEL}" == "force" ]] || die "STRATEGY_TEST_LEVEL должен быть quick, standard или force"
command -v curl >/dev/null || die "не найден curl"
command -v sudo >/dev/null || die "не найден sudo"

if (( $# > 0 )); then TEST_DOMAINS="$*"; fi

mkdir -p "${SCRIPT_DIR}/logs/tests"
timestamp="$(date +%Y%m%d-%H%M%S)"
log_file="${SCRIPT_DIR}/logs/tests/nfqws${NFQWS_ENGINE}-${timestamp}.log"

# nfqws drops root before loading Lua. A project under a mode-700 home directory
# is therefore intentionally inaccessible. Stage the official tester in /tmp
# instead of weakening permissions on the user's home directory.
test_runtime="$(mktemp -d /tmp/3b-blockcheck.XXXXXX)"
cleanup_runtime() { rm -rf -- "${test_runtime}"; }
trap cleanup_runtime EXIT
trap 'cleanup_runtime; exit 130' INT TERM
if [[ "${NFQWS_ENGINE}" == "1" ]]; then
    cp -a "${SCRIPT_DIR}/vendor/zapret1/." "${test_runtime}/"
else
    cp -a "${SCRIPT_DIR}/vendor/zapret2/." "${test_runtime}/"
fi
chmod -R a+rX "${test_runtime}"

echo "Останавливаю действующую стратегию 3B, чтобы она не исказила результаты..."
"${SCRIPT_DIR}/stop.sh"

export SCANLEVEL="${TEST_LEVEL}"
export REPEATS="${TEST_REPEATS}"
export PARALLEL="${TEST_PARALLEL}"
export BATCH="${TEST_BATCH}"
export IPVS="${TEST_IPV}"
export CURL_MAX_TIME="${TEST_CURL_MAX_TIME}"
[[ -n "${TEST_DOMAINS}" ]] && export DOMAINS="${TEST_DOMAINS}"

# Preload blockcheck's DNS cache: domain=ip pairs separated by spaces.
# This preserves the tested hostname/SNI while forcing a reachable frontend IP.
if [[ -n "${TEST_IP_OVERRIDES}" ]]; then
    echo "Фиксированные IP для теста:"
    for mapping in ${TEST_IP_OVERRIDES}; do
        [[ "${mapping}" == *=* ]] || die "неверный STRATEGY_TEST_IP_OVERRIDES: ${mapping}"
        override_domain="${mapping%%=*}"
        override_ip="${mapping#*=}"
        [[ "${override_domain}" =~ ^[A-Za-z0-9.-]+$ ]] || die "некорректный домен override: ${override_domain}"
        [[ "${override_ip}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "сейчас поддерживается только IPv4 override: ${override_ip}"
        cache_host="$(printf '%s' "${override_domain,,}" | sed -e 's|[\./?&#@%*$^:~=!()+-]|_|g')"
        printf -v count_name 'DNSCACHE_%s_4_COUNT' "${cache_host}"
        printf -v value_name 'DNSCACHE_%s_4_0' "${cache_host}"
        export "${count_name}=1" "${value_name}=${override_ip}"
        echo "  ${override_domain} -> ${override_ip}"
    done
fi

echo "Тестер: nfqws${NFQWS_ENGINE}; level=${TEST_LEVEL}; repeats=${TEST_REPEATS}; IPv=${TEST_IPV}"
[[ -n "${TEST_DOMAINS}" ]] && echo "Домены: ${TEST_DOMAINS}"
echo "Полный лог: ${log_file}"
echo

set +e
if [[ "${NFQWS_ENGINE}" == "1" ]]; then
    tester_root="${test_runtime}"
    [[ -x "${tester_root}/blockcheck.sh" && -x "${tester_root}/nfq/nfqws" ]] || die "неполный комплект tester-а zapret1"
    export ZAPRET_BASE="${tester_root}"
    export ZAPRET_RW="${SCRIPT_DIR}/logs/tests/zapret1-state"
    export NFQWS="${tester_root}/nfq/nfqws"
    export MDIG="${tester_root}/mdig/mdig"
    export SKIP_TPWS=1
    "${tester_root}/blockcheck.sh" 2>&1 | tee "${log_file}"
    test_rc=${PIPESTATUS[0]}
else
    tester_root="${test_runtime}"
    [[ -x "${tester_root}/blockcheck2.sh" && -x "${tester_root}/nfq2/nfqws2" ]] || die "неполный комплект tester-а zapret2"
    export ZAPRET_BASE="${tester_root}"
    export ZAPRET_RW="${SCRIPT_DIR}/logs/tests/zapret2-state"
    export NFQWS2="${tester_root}/nfq2/nfqws2"
    export MDIG="${tester_root}/mdig/mdig"
    "${tester_root}/blockcheck2.sh" 2>&1 | tee "${log_file}"
    test_rc=${PIPESTATUS[0]}
fi
set -e

echo
if (( test_rc == 0 )); then
    echo "Тест завершён. Итоговые стратегии ищите в секции SUMMARY:"
    echo "  ${log_file}"
    result_dir="${SCRIPT_DIR}/logs/tests/results/nfqws${NFQWS_ENGINE}-${timestamp}"
    echo
    if "${SCRIPT_DIR}/scripts/strategy-report.sh" "${log_file}" "${NFQWS_ENGINE}" "${result_dir}"; then
        echo "Кандидаты разложены по доменам и протоколам."
    else
        report_rc=$?
        (( report_rc == 2 )) || echo "Не удалось разобрать SUMMARY (код ${report_rc})." >&2
    fi
    echo "Переносить проверенные кандидаты нужно в $([[ "${NFQWS_ENGINE}" == "1" ]] && echo strategies/ || echo strategies2/)."
else
    echo "Тестер завершился с кодом ${test_rc}. Диагностика сохранена в ${log_file}." >&2
fi
echo "3B оставлен остановленным. После выбора стратегии запустите: sudo ./start.sh"
exit "${test_rc}"
