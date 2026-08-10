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
TEST_LEVEL="${STRATEGY_TEST_LEVEL-}"
TEST_REPEATS="${STRATEGY_TEST_REPEATS-}"
TEST_BATCH="${STRATEGY_TEST_BATCH:-0}"
TEST_PARALLEL="${STRATEGY_TEST_PARALLEL:-0}"
TEST_IPV="${STRATEGY_TEST_IPV:-4}"
TEST_DOMAINS="${STRATEGY_TEST_DOMAINS:-}"
TEST_CURL_MAX_TIME="${STRATEGY_TEST_CURL_MAX_TIME:-3}"
TEST_IP_OVERRIDES="${STRATEGY_TEST_IP_OVERRIDES-}"
TEST_PROGRESS="${STRATEGY_TEST_PROGRESS:-1}"
TEST_TOTAL="${STRATEGY_TEST_TOTAL-}"
TEST_STOP_AFTER_FOUND="${STRATEGY_TEST_STOP_AFTER_FOUND-}"

die() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }

read_answer() {
    local __name="$1" prompt="$2" answer
    if ! IFS= read -r -p "${prompt}" answer; then
        die "невозможно прочитать интерактивный параметр ${__name}; заполните его в .env"
    fi
    printf -v "${__name}" '%s' "${answer}"
}

if [[ -z "${TEST_LEVEL}" ]]; then
    echo "Режим поиска STRATEGY_TEST_LEVEL определяет глубину перебора:"
    echo "  1) quick    — быстрый поиск, останавливает ветки после раннего успеха"
    echo "  2) standard — разумный баланс времени и числа вариантов (рекомендуется)"
    echo "  3) force    — максимально полный и самый долгий перебор"
    while :; do
        read_answer TEST_LEVEL "Выберите режим [2/standard]: "
        case "${TEST_LEVEL}" in
            ''|2|standard) TEST_LEVEL=standard; break ;;
            1|quick) TEST_LEVEL=quick; break ;;
            3|force) TEST_LEVEL=force; break ;;
            *) echo "Введите 1, 2, 3 либо quick, standard, force." ;;
        esac
    done
    echo
fi

if [[ -z "${TEST_REPEATS}" ]]; then
    echo "STRATEGY_TEST_REPEATS — сколько раз подряд стратегия должна успешно пройти проверку."
    echo "Больше повторов повышает надёжность, но пропорционально увеличивает время."
    while :; do
        read_answer TEST_REPEATS "Количество повторов [3]: "
        TEST_REPEATS="${TEST_REPEATS:-3}"
        [[ "${TEST_REPEATS}" =~ ^[1-9][0-9]*$ ]] && break
        echo "Введите целое число больше нуля."
    done
    echo
fi

if [[ -z "${TEST_TOTAL}" ]]; then
    echo "STRATEGY_TEST_TOTAL — сохранённая оценка общего числа стратегий для progress bar."
    echo "0 запускает предварительный подсчёт; готовое число (например 1000) позволяет начать сразу."
    echo "Если реальных стратегий больше оценки, тест всё равно продолжится после 100%."
    while :; do
        read_answer TEST_TOTAL "Оценка общего количества [0/подсчитать]: "
        TEST_TOTAL="${TEST_TOTAL:-0}"
        [[ "${TEST_TOTAL}" =~ ^[0-9]+$ ]] && break
        echo "Введите целое число от нуля."
    done
    echo
fi

if [[ -z "${TEST_STOP_AFTER_FOUND}" ]]; then
    echo "STRATEGY_TEST_STOP_AFTER_FOUND — сколько полностью проверенных стратегий нужно найти."
    echo "После достижения числа tester корректно остановится; 0 означает пройти весь перебор."
    while :; do
        read_answer TEST_STOP_AFTER_FOUND "Остановиться после количества находок [0/не останавливать]: "
        TEST_STOP_AFTER_FOUND="${TEST_STOP_AFTER_FOUND:-0}"
        [[ "${TEST_STOP_AFTER_FOUND}" =~ ^[0-9]+$ ]] && break
        echo "Введите целое число от нуля."
    done
    echo
fi

if [[ -z "${TEST_IP_OVERRIDES}" ]]; then
    echo "STRATEGY_TEST_IP_OVERRIDES — принудительные IPv4-адреса для отдельных доменов."
    echo "Это сохраняет исходные hostname/SNI, но направляет соединение на указанный frontend."
    echo "Формат: domain=IPv4; несколько пар разделяются пробелами."
    echo "Пример: whatsapp.com=57.144.251.32 web.whatsapp.com=57.144.251.32"
    echo "Нажмите Enter, чтобы не подменять адреса и использовать обычный DNS."
    read_answer TEST_IP_OVERRIDES "IP overrides [без подмены]: "
    echo
fi

[[ "${NFQWS_ENGINE}" == "1" || "${NFQWS_ENGINE}" == "2" ]] || die "NFQWS_ENGINE должен быть 1 или 2"
[[ "${TEST_REPEATS}" =~ ^[1-9][0-9]*$ ]] || die "STRATEGY_TEST_REPEATS должен быть положительным числом"
[[ "${TEST_LEVEL}" == "quick" || "${TEST_LEVEL}" == "standard" || "${TEST_LEVEL}" == "force" ]] || die "STRATEGY_TEST_LEVEL должен быть quick, standard или force"
[[ "${TEST_PROGRESS}" == "0" || "${TEST_PROGRESS}" == "1" ]] || die "STRATEGY_TEST_PROGRESS должен быть 0 или 1"
[[ "${TEST_TOTAL}" =~ ^[0-9]+$ ]] || die "STRATEGY_TEST_TOTAL должен быть целым числом от 0"
[[ "${TEST_STOP_AFTER_FOUND}" =~ ^[0-9]+$ ]] || die "STRATEGY_TEST_STOP_AFTER_FOUND должен быть целым числом от 0"
command -v curl >/dev/null || die "не найден curl"
command -v sudo >/dev/null || die "не найден sudo"

if (( $# > 0 )); then TEST_DOMAINS="$*"; fi

mkdir -p "${SCRIPT_DIR}/logs/tests"
timestamp="$(date +%Y%m%d-%H%M%S)"
log_file="${SCRIPT_DIR}/logs/tests/nfqws${NFQWS_ENGINE}-${timestamp}.log"
result_dir="${SCRIPT_DIR}/logs/tests/results/nfqws${NFQWS_ENGINE}-${timestamp}"
mkdir -p "${result_dir}"

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
    tester_cmd=("${tester_root}/blockcheck.sh")
else
    tester_root="${test_runtime}"
    [[ -x "${tester_root}/blockcheck2.sh" && -x "${tester_root}/nfq2/nfqws2" ]] || die "неполный комплект tester-а zapret2"
    export ZAPRET_BASE="${tester_root}"
    export ZAPRET_RW="${SCRIPT_DIR}/logs/tests/zapret2-state"
    export NFQWS2="${tester_root}/nfq2/nfqws2"
    export MDIG="${tester_root}/mdig/mdig"
    tester_cmd=("${tester_root}/blockcheck2.sh")
fi

strategy_total="${TEST_TOTAL}"
if (( strategy_total > 0 )); then
    echo "Стратегий по сохранённой оценке: ${strategy_total}"
elif [[ "${TEST_PROGRESS}" == "1" ]]; then
    echo "Считаю стратегии перед запуском..."
    plan_output="$(SKIP_DNSCHECK=1 SKIP_IPBLOCK=1 BATCH=1 REPEATS=1 SIMULATE=1 SIM_SUCCESS_RATE=0 "${tester_cmd[@]}" 2>&1)"
    strategy_total="$(printf '%s\n' "${plan_output}" | grep -cE '^- curl_test_.* : (nfqws2?|dvtws2?|winws2?) ' || true)"
    [[ "${strategy_total}" =~ ^[0-9]+$ ]] || strategy_total=0
    if (( strategy_total > 0 )); then
        [[ "${TEST_LEVEL}" == "force" ]] && estimate_note="" || estimate_note=" (оценка; standard/quick может пропускать лишние ветки)"
        echo "Стратегий к проверке: ${strategy_total}${estimate_note}"
    else
        echo "Не удалось заранее определить число стратегий; прогресс покажет обработанное количество."
    fi
fi
(( TEST_STOP_AFTER_FOUND > 0 )) && echo "Автостоп: после ${TEST_STOP_AFTER_FOUND} полностью проверенных находок."
echo

"${tester_cmd[@]}" 2>&1 | tee "${log_file}" | "${SCRIPT_DIR}/scripts/live-strategy-capture.sh" \
    "${NFQWS_ENGINE}" "${result_dir}" "${strategy_total}" "${TEST_STOP_AFTER_FOUND}"
test_rc=${PIPESTATUS[0]}
if [[ -f "${result_dir}/.stopped-after-found" ]]; then
    test_rc=0
    stopped_early=1
else
    stopped_early=0
fi
found_count="$(wc -l < "${result_dir}/index.live.tsv" 2>/dev/null || printf '0')"
found_count="${found_count//[[:space:]]/}"
[[ "${found_count}" =~ ^[0-9]+$ ]] || found_count=0
set -e

echo
if (( test_rc == 0 )); then
    if (( stopped_early == 1 )); then
        echo "Тест корректно остановлен после заданного числа находок."
        echo "Проверенные кандидаты уже сохранены в ${result_dir}/domains/"
        echo "Полного SUMMARY и common/ при ранней остановке не будет."
    else
        echo "Тест завершён. Итоговые стратегии ищите в секции SUMMARY:"
        echo "  ${log_file}"
        if (( TEST_STOP_AFTER_FOUND > 0 && found_count < TEST_STOP_AFTER_FOUND )); then
            echo "Цель не набрана: найдено ${found_count} из ${TEST_STOP_AFTER_FOUND}; сохраняю всё найденное."
        else
            echo "Найдено успешных стратегий: ${found_count}."
        fi
        echo
        if "${SCRIPT_DIR}/scripts/strategy-report.sh" "${log_file}" "${NFQWS_ENGINE}" "${result_dir}"; then
            echo "Кандидаты разложены по доменам и протоколам."
        else
            report_rc=$?
            (( report_rc == 2 )) || echo "Не удалось разобрать SUMMARY (код ${report_rc})." >&2
        fi
    fi
    echo "Переносить проверенные кандидаты нужно в $([[ "${NFQWS_ENGINE}" == "1" ]] && echo strategies/ || echo strategies2/)."
else
    echo "Тестер завершился с кодом ${test_rc}. Диагностика сохранена в ${log_file}." >&2
fi
echo "3B оставлен остановленным. После выбора стратегии запустите: sudo ./start.sh"
exit "${test_rc}"
